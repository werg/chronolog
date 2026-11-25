import {
  GROUP_COLLECTIVE_ID,
  platformObjectId,
  platformOp,
  sealedOp,
  sqlStatement,
  sqlValue,
  type ProgramStep,
} from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import type { DeterministicMaterializer } from './materializer.js'
import { MaterializerFixture, ROOT_KEY, replayProposal, rows, testKey } from './test-fixtures.js'
import type { ReplayProposal } from './types.js'

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())

const ALICE = testKey(0x10)
const BOB = testKey(0x20)
const CAROL = testKey(0x30)

/** Appends transactions in order and reports each outcome as `accepted` or its rejection code. */
class Ledger {
  readonly #transactions: ReplayProposal[] = []
  #clock = 1n

  constructor(readonly materializer: DeterministicMaterializer) {}

  get transactions(): readonly ReplayProposal[] { return [...this.#transactions] }

  async submit(author: Uint8Array, ...steps: readonly (ProgramStep | string)[]): Promise<{ readonly outcome: string; readonly txId: Uint8Array; readonly step: number | null }> {
    const id = `tx-${this.#clock}`
    const transaction = await replayProposal(this.#clock, id, steps, this.materializer.executionManifestDigest, author)
    this.#clock += 1n
    this.#transactions.push(transaction)
    await this.materializer.materialize(this.#transactions)
    const outcome = this.materializer.outcome(transaction.txId)!
    return { outcome: outcome.rejectionCode ?? 'accepted', txId: transaction.txId, step: outcome.failingStatementIndex }
  }

  async expectOutcome(expected: string, author: Uint8Array, ...steps: readonly (ProgramStep | string)[]): Promise<Uint8Array> {
    const result = await this.submit(author, ...steps)
    expect(result.outcome, steps.map((step) => typeof step === 'string' ? step : 'sql' in step ? step.sql : step.op).join(' | ')).toBe(expected)
    return result.txId
  }
}

async function ledger(options: { readonly forkSeeding?: boolean } = {}): Promise<Ledger> {
  const { materializer } = await fixtures.open(options)
  return new Ledger(materializer)
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex').toUpperCase()

/** Root registers `notes`, admits Alice and Bob as writers of their own rows. */
async function notesLedger(): Promise<Ledger> {
  const book = await ledger()
  await book.expectOutcome('accepted', ROOT_KEY,
    'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, status TEXT NOT NULL DEFAULT \'draft\')')
  await book.expectOutcome('accepted', ALICE, "INSERT INTO notes (id, body) VALUES (1, 'alice one'), (2, 'alice two')")
  await book.expectOutcome('accepted', BOB, "INSERT INTO notes (id, body) VALUES (10, 'bob ten')")
  return book
}

describe('owner-controlled rows: identity and the owner column', () => {
  it('stamps new rows with the signing key and lets only the owner change them', async () => {
    const book = await notesLedger()
    expect(rows(book.materializer, 'SELECT id, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM notes ORDER BY id'))
      .toEqual([['1', hex(ALICE)], ['2', hex(ALICE)], ['10', hex(BOB)]])
    await book.expectOutcome('accepted', ALICE, "UPDATE notes SET body = 'edited' WHERE id = 1")
    await book.expectOutcome('policy:notes:update', BOB, "UPDATE notes SET body = 'stolen' WHERE id = 1")
    await book.expectOutcome('policy:notes:delete', BOB, 'DELETE FROM notes WHERE id = 2')
    await book.expectOutcome('accepted', ALICE, 'DELETE FROM notes WHERE id = 2')
    expect(rows(book.materializer, 'SELECT id, body FROM notes ORDER BY id')).toEqual([['1', 'edited'], ['10', 'bob ten']])
  })

  it('never skips silently: a statement touching another owner\'s row aborts the whole transaction', async () => {
    const book = await notesLedger()
    const result = await book.submit(ALICE, "UPDATE notes SET status = 'done' WHERE id = 1", "UPDATE notes SET status = 'done'")
    expect(result).toMatchObject({ outcome: 'policy:notes:update', step: 1 })
    expect(rows(book.materializer, "SELECT count(*) FROM notes WHERE status = 'done'")).toEqual([['0']])
    await book.expectOutcome('accepted', ALICE,
      "UPDATE notes SET status = 'done' WHERE chronolog_owner IN (SELECT id FROM chronolog_my_owner_ids_update)")
    expect(rows(book.materializer, "SELECT id FROM notes WHERE status = 'done' ORDER BY id")).toEqual([['1'], ['2']])
  })

  it('refuses inserting as another owner and re-owning a row', async () => {
    const book = await notesLedger()
    await book.expectOutcome('policy:notes:insert', ALICE, sqlStatement('INSERT INTO notes (id, body, chronolog_owner) VALUES (3, ?, (SELECT id FROM chronolog_principals WHERE key = ?))', ['x', BOB]))
    await book.expectOutcome('policy:notes:insert', ALICE, 'INSERT INTO notes (id, body, chronolog_owner) SELECT 4, body, chronolog_owner FROM notes WHERE id = 10')
    await book.expectOutcome('policy:notes:update', ALICE, sqlStatement('UPDATE notes SET chronolog_owner = (SELECT id FROM chronolog_principals WHERE key = ?) WHERE id = 1', [BOB]))
    // The policy check fails closed, before the NOT NULL constraint.
    await book.expectOutcome('policy:notes:insert', ALICE, 'INSERT INTO notes (id, body, chronolog_owner) VALUES (5, \'x\', NULL)')
  })

  it('applies to the root administrator and schema administrators like anyone else', async () => {
    const book = await notesLedger()
    await book.expectOutcome('policy:notes:update', ROOT_KEY, "UPDATE notes SET body = 'admin' WHERE id = 1")
    await book.expectOutcome('policy:notes:delete', ROOT_KEY, 'DELETE FROM notes WHERE id = 10')
    await book.expectOutcome('policy:notes:update', ROOT_KEY, sqlStatement('UPDATE notes SET chronolog_owner = (SELECT id FROM chronolog_principals WHERE key = ?) WHERE id = 1', [ROOT_KEY]))
  })

  it('cannot be bypassed with REPLACE, UPSERT or RETURNING', async () => {
    const book = await notesLedger()
    await book.expectOutcome('policy:notes:delete', ALICE, "INSERT OR REPLACE INTO notes (id, body) VALUES (10, 'replaced')")
    await book.expectOutcome('policy:notes:delete', ALICE, "REPLACE INTO notes (id, body) VALUES (10, 'replaced')")
    await book.expectOutcome('policy:notes:delete', ALICE, 'UPDATE OR REPLACE notes SET id = 10 WHERE id = 1')
    await book.expectOutcome('policy:notes:update', ALICE, "INSERT INTO notes (id, body) VALUES (10, 'x') ON CONFLICT (id) DO UPDATE SET body = excluded.body")
    await book.expectOutcome('accepted', ALICE, "INSERT INTO notes (id, body) VALUES (1, 'upsert') ON CONFLICT (id) DO UPDATE SET body = excluded.body RETURNING id")
    // Explicit conflict handling never writes the other owner's row.
    await book.expectOutcome('accepted', ALICE, "INSERT OR IGNORE INTO notes (id, body) VALUES (10, 'ignored')")
    await book.expectOutcome('accepted', ALICE, "INSERT INTO notes (id, body) VALUES (10, 'nothing') ON CONFLICT DO NOTHING")
    expect(rows(book.materializer, 'SELECT id, body, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM notes WHERE id IN (1, 10) ORDER BY id'))
      .toEqual([['1', 'upsert', hex(ALICE)], ['10', 'bob ten', hex(BOB)]])
  })

  it('refuses direct calls to the policy function', async () => {
    const book = await notesLedger()
    await book.expectOutcome('denied', ALICE, "SELECT chronolog_policy_violation('notes', 'update')")
  })
})

describe('owner-controlled rows: schema administration', () => {
  it('requires explicit DDL permission, including for triggers', async () => {
    const book = await notesLedger()
    for (const sql of [
      'CREATE TABLE extra (id INTEGER PRIMARY KEY)',
      'CREATE INDEX notes_body ON notes (body)',
      'CREATE VIEW v AS SELECT 1',
      "CREATE TRIGGER t AFTER INSERT ON notes BEGIN SELECT 1; END",
      'ALTER TABLE notes ADD COLUMN extra TEXT',
      'DROP TABLE notes',
    ]) {
      await book.expectOutcome('denied', ALICE, sql)
    }
    await book.expectOutcome('accepted', ALICE, 'SELECT count(*) FROM notes')
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE INDEX notes_body ON notes (body)')
  })

  it('puts every new table under owner checks as it is created, and lets admins alter and drop them', async () => {
    const book = await ledger()
    // The CREATE itself registers the table, so the next statement is already checked.
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE loose (id INTEGER PRIMARY KEY, v TEXT)', "INSERT INTO loose (id, v) VALUES (1, 'root')")
    expect(rows(book.materializer, 'SELECT name FROM chronolog_tables')).toEqual([['loose']])
    expect(rows(book.materializer, 'SELECT hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM loose')).toEqual([[hex(ROOT_KEY)]])
    await book.expectOutcome('policy:loose:update', ALICE, "UPDATE loose SET v = 'alice' WHERE id = 1")
    await book.expectOutcome('platform:no_primary_key', ROOT_KEY, 'CREATE TABLE nokey (v TEXT)')
    await book.expectOutcome('denied', ALICE, 'CREATE TABLE mine (id INTEGER PRIMARY KEY)')
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()))')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO items (id, name) VALUES (1, 'a')")
    // Adding a column regenerates the platform triggers so column caps cover it.
    await book.expectOutcome('accepted', ROOT_KEY, 'ALTER TABLE items ADD COLUMN price REAL')
    await book.expectOutcome('accepted', ALICE, 'UPDATE items SET price = 2.5 WHERE id = 1')
    await book.expectOutcome('policy:items:update', BOB, 'UPDATE items SET price = 0 WHERE id = 1')
    // Renaming a table keeps it registered under its new name, with its grants.
    await book.expectOutcome('accepted', ALICE, platformOp.grant({ table: 'items', grantee: CAROL, operations: ['update'] }))
    await book.expectOutcome('accepted', ROOT_KEY, 'ALTER TABLE items RENAME TO goods')
    expect(rows(book.materializer, 'SELECT name FROM chronolog_tables ORDER BY name')).toEqual([['goods'], ['loose']])
    expect(rows(book.materializer, "SELECT name FROM sqlite_schema WHERE name LIKE 'chronolog_k_%' ORDER BY name")).toEqual([
      ['chronolog_k_goods_del'], ['chronolog_k_goods_ins'], ['chronolog_k_goods_upd'],
      ['chronolog_k_loose_del'], ['chronolog_k_loose_ins'], ['chronolog_k_loose_upd']])
    await book.expectOutcome('policy:goods:update', BOB, 'UPDATE goods SET price = 0 WHERE id = 1')
    await book.expectOutcome('accepted', CAROL, 'UPDATE goods SET price = 3 WHERE id = 1')
    // Dropping a table unregisters it.
    await book.expectOutcome('accepted', ROOT_KEY, 'DROP TABLE goods', 'DROP TABLE loose')
    expect(rows(book.materializer, 'SELECT count(*) FROM chronolog_tables')).toEqual([['0']])
    expect(rows(book.materializer, "SELECT count(*) FROM sqlite_schema WHERE name LIKE 'chronolog_k_%'")).toEqual([['0']])
  })

  it('refuses tables that cannot be owner-checked, and checks rows written right after the CREATE', async () => {
    const book = await ledger()
    // CREATE … AS SELECT has rows but no primary key or owner column.
    await book.expectOutcome('platform:no_primary_key', ROOT_KEY, 'CREATE TABLE copied AS SELECT 1 AS id')
    await book.expectOutcome('policy:forged:insert', ROOT_KEY,
      'CREATE TABLE forged (id INTEGER PRIMARY KEY, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()))',
      'INSERT INTO forged VALUES (1, 99)')
    await book.expectOutcome('platform:owner_column_invalid', ROOT_KEY,
      'CREATE TABLE bad (id INTEGER PRIMARY KEY, chronolog_owner BLOB)')
  })

  it('protects platform triggers, views, tables and the owner column', async () => {
    const book = await notesLedger()
    for (const sql of [
      'DROP TRIGGER chronolog_k_notes_upd',
      'CREATE TRIGGER chronolog_k_x BEFORE UPDATE ON notes BEGIN SELECT 1; END',
      'DROP VIEW chronolog_my_owner_ids_update',
      'CREATE VIEW chronolog_x AS SELECT 1',
      'ALTER TABLE notes DROP COLUMN chronolog_owner',
      "INSERT INTO chronolog_grants (grant_id, tbl, grantor, grantee_key, op_insert, op_update, op_delete, created_tx) VALUES (zeroblob(32), 'notes', zeroblob(32), zeroblob(32), 1, 1, 1, x'00')",
      "UPDATE chronolog_collective_members SET role = 'admin'",
      'DELETE FROM chronolog_tables',
    ]) {
      await book.expectOutcome('denied', ROOT_KEY, sql)
    }
    await book.expectOutcome('schema_unregistered', ROOT_KEY, 'ALTER TABLE notes RENAME COLUMN chronolog_owner TO owner')
  })

  it('refuses app triggers that use RAISE(IGNORE)', async () => {
    const book = await notesLedger()
    await book.expectOutcome('trigger_ignore', ROOT_KEY,
      'CREATE TRIGGER notes_skip BEFORE UPDATE ON notes WHEN OLD.status = \'final\' BEGIN SELECT raise /* c */ ( ignore ); END')
    await book.expectOutcome('accepted', ROOT_KEY,
      "CREATE TRIGGER notes_final BEFORE UPDATE ON notes WHEN OLD.status = 'final' BEGIN SELECT RAISE(ABORT, 'final'); END")
  })

  it('lints foreign-key actions: cascades only along owner-composite keys', async () => {
    const book = await notesLedger()
    await book.expectOutcome('platform:fk_action', ROOT_KEY,
      'CREATE TABLE comments (id INTEGER PRIMARY KEY, note_id INTEGER REFERENCES notes (id) ON DELETE CASCADE)')
    await book.expectOutcome('platform:fk_action', ROOT_KEY,
      'CREATE TABLE comments (id INTEGER PRIMARY KEY, note_id INTEGER REFERENCES notes (id) ON DELETE SET NULL)')
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE refs (id INTEGER PRIMARY KEY, note_id INTEGER REFERENCES notes (id) ON DELETE RESTRICT)')
  })
})

describe('owner-controlled rows: foreign keys, app triggers and recursion', () => {
  async function parentChild(): Promise<Ledger> {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      `CREATE TABLE parents (id INTEGER PRIMARY KEY, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), UNIQUE (id, chronolog_owner))`,
      `CREATE TABLE children (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL,
         chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()),
         FOREIGN KEY (parent_id, chronolog_owner) REFERENCES parents (id, chronolog_owner) ON UPDATE CASCADE ON DELETE CASCADE)`,
      'CREATE TABLE links (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parents (id))')
    await book.expectOutcome('accepted', ALICE, 'INSERT INTO parents (id) VALUES (1)', 'INSERT INTO children (id, parent_id) VALUES (1, 1), (2, 1)')
    return book
  }

  it('cascades through the owner\'s own children and refuses cross-owner children', async () => {
    const book = await parentChild()
    // Bob cannot hang a child under Alice's parent with his own owner value.
    await book.expectOutcome('constraint', BOB, 'INSERT INTO children (id, parent_id) VALUES (3, 1)')
    // A plain reference by Bob blocks Alice's delete instead of cascading into his row.
    await book.expectOutcome('accepted', BOB, 'INSERT INTO links (id, parent_id) VALUES (1, 1)')
    await book.expectOutcome('constraint', ALICE, 'DELETE FROM parents WHERE id = 1')
    await book.expectOutcome('accepted', BOB, 'DELETE FROM links')
    await book.expectOutcome('accepted', ALICE, 'DELETE FROM parents WHERE id = 1')
    expect(rows(book.materializer, 'SELECT count(*) FROM children')).toEqual([['0']])
  })

  it('checks app-trigger writes as the signer, so triggers can narrow but not widen', async () => {
    const book = await parentChild()
    await book.expectOutcome('accepted', BOB, 'INSERT INTO parents (id) VALUES (2)')
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE audit (id INTEGER PRIMARY KEY, note TEXT, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()))',
      // Touches every parent on any child insert: it may only touch the signer's own.
      "CREATE TRIGGER children_touch AFTER INSERT ON children BEGIN UPDATE parents SET id = id WHERE id = 2; END")
    await book.expectOutcome('policy:parents:update', ALICE, 'INSERT INTO children (id, parent_id) VALUES (5, 1)')
    await book.expectOutcome('accepted', ROOT_KEY,
      'DROP TRIGGER children_touch',
      // Narrowing: only the parent's owner may add children; an audit row is written as the signer.
      "CREATE TRIGGER children_audit AFTER INSERT ON children BEGIN INSERT INTO audit (note) VALUES ('child ' || NEW.id); END")
    await book.expectOutcome('accepted', ALICE, 'INSERT INTO children (id, parent_id) VALUES (5, 1)')
    expect(rows(book.materializer, 'SELECT note, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM audit')).toEqual([['child 5', hex(ALICE)]])
  })

  it('aborts unguarded recursion deterministically and runs guarded recursion once', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ROOT_KEY,
      "CREATE TRIGGER notes_loop AFTER UPDATE OF body ON notes BEGIN UPDATE notes SET body = body || '!' WHERE id = NEW.id; END")
    await book.expectOutcome('error', ALICE, "UPDATE notes SET body = 'x' WHERE id = 1")
    await book.expectOutcome('accepted', ROOT_KEY,
      'DROP TRIGGER notes_loop',
      "CREATE TRIGGER notes_once AFTER UPDATE OF body ON notes WHEN NEW.body NOT LIKE '%!' BEGIN UPDATE notes SET body = body || '!' WHERE id = NEW.id; END")
    await book.expectOutcome('accepted', ALICE, "UPDATE notes SET body = 'x' WHERE id = 1")
    expect(rows(book.materializer, 'SELECT body FROM notes WHERE id = 1')).toEqual([['x!']])
  })
})

describe('owner-controlled rows: grants', () => {
  it('does not confuse NUL-containing TEXT keys, BLOB keys or adjacent REAL keys', async () => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE keyed (id ANY PRIMARY KEY NOT NULL, body TEXT, status TEXT) STRICT')
    const keys = ['a\0one', 'a\0two', new Uint8Array([97, 0, 111, 110, 101]), sqlValue.real(1.5), sqlValue.real(1.5000000000000002)]
    for (const key of keys) await book.expectOutcome('accepted', ALICE, sqlStatement('INSERT INTO keyed (id, body) VALUES (?, ?)', [key, 'original']))
    await book.expectOutcome('accepted', ALICE, platformOp.grant({ table: 'keyed', grantee: BOB, rowKey: [keys[0]], operations: ['update', 'delete'] }))
    await book.expectOutcome('accepted', BOB, sqlStatement('UPDATE keyed SET status = ? WHERE id = ?', ['ok', keys[0]]))
    for (const key of keys.slice(1)) {
      await book.expectOutcome('policy:keyed:update', BOB, sqlStatement('UPDATE keyed SET status = ? WHERE id = ?', ['no', key]))
      await book.expectOutcome('policy:keyed:delete', BOB, sqlStatement('DELETE FROM keyed WHERE id = ?', [key]))
    }
    await book.expectOutcome('accepted', ALICE, platformOp.grant({ table: 'keyed', grantee: BOB, rowKey: [keys[3]], operations: ['update'] }))
    await book.expectOutcome('accepted', BOB, sqlStatement('UPDATE keyed SET status = ? WHERE id = ?', ['real ok', keys[3]]))
    await book.expectOutcome('policy:keyed:update', BOB, sqlStatement('UPDATE keyed SET status = ? WHERE id = ?', ['no', keys[4]]))
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'keyed', rowKey: [keys[0]], toOwner: BOB }))
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(await platformObjectId(offer, 0)))
    await book.expectOutcome('accepted', BOB, sqlStatement('UPDATE keyed SET body = ? WHERE id = ?', ['new owner', keys[0]]))
  })

  it('requires actual non-NULL primary keys instead of sharing authority across ambiguous rows', async () => {
    const book = await ledger()
    // DoltLite makes these PKs NOT NULL even when the SQL omits the clause.
    // Registration checks actual metadata rather than guessing from SQL text.
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE text_keys (id TEXT PRIMARY KEY, body TEXT)',
      'CREATE TABLE composite_keys (a INTEGER, b TEXT, PRIMARY KEY(a, b))',
      'CREATE TABLE descending_keys (id INTEGER PRIMARY KEY DESC)')
    await book.expectOutcome('constraint', ALICE, 'INSERT INTO text_keys(id) VALUES(NULL)')
    await book.expectOutcome('constraint', ALICE, "INSERT INTO composite_keys(a,b) VALUES(NULL,'x')")
    await book.expectOutcome('constraint', ALICE, 'INSERT INTO descending_keys(id) VALUES(NULL)')
  })

  it('treats case, storage type and exact numeric changes as changes outside column caps', async () => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE capped (id INTEGER PRIMARY KEY, body TEXT COLLATE NOCASE, n ANY, status TEXT) STRICT')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO capped (id, body, n) VALUES (1, 'secret', 1)",
      platformOp.grant({ table: 'capped', grantee: BOB, operations: ['update'], columns: ['status'] }))
    await book.expectOutcome('policy:capped:update', BOB, "UPDATE capped SET body = 'SECRET', status = 'done' WHERE id = 1")
    await book.expectOutcome('policy:capped:update', BOB, 'UPDATE capped SET n = 1.0 WHERE id = 1')
    await book.expectOutcome('accepted', BOB, "UPDATE capped SET body = 'secret', n = 1, status = 'done' WHERE id = 1")
    expect(rows(book.materializer, 'SELECT body, typeof(n), status FROM capped')).toEqual([['secret', 'integer', 'done']])
  })

  it('revokes grants when rows are deleted, replaced or re-keyed, including inside application triggers', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ALICE, platformOp.grant({ table: 'notes', grantee: BOB, rowKey: [1n], operations: ['update', 'delete'] }))
    await book.expectOutcome('accepted', ALICE, 'DELETE FROM notes WHERE id = 1', "INSERT INTO notes (id, body) VALUES (1, 'replacement')")
    await book.expectOutcome('policy:notes:update', BOB, "UPDATE notes SET body = 'old grant' WHERE id = 1")
    await book.expectOutcome('accepted', ALICE, platformOp.grant({ table: 'notes', grantee: BOB, rowKey: [1n], operations: ['update'] }))
    await book.expectOutcome('accepted', ALICE, 'UPDATE notes SET id = 3 WHERE id = 1', "INSERT INTO notes (id, body) VALUES (1, 'another replacement')")
    await book.expectOutcome('policy:notes:update', BOB, "UPDATE notes SET body = 'old grant' WHERE id IN (1, 3)")

    // An AFTER DELETE trigger must not reuse a still-live old row grant on a
    // replacement it creates during the same SQL statement.
    await book.expectOutcome('accepted', ALICE,
      platformOp.grant({ table: 'notes', grantee: BOB, operations: ['insert'] }),
      platformOp.grant({ table: 'notes', grantee: BOB, rowKey: [1n], operations: ['update', 'delete'] }))
    await book.expectOutcome('accepted', ROOT_KEY, `CREATE TRIGGER replace_deleted AFTER DELETE ON notes WHEN OLD.id = 1 BEGIN
      INSERT INTO notes (id, body, chronolog_owner) VALUES (OLD.id, 'trigger replacement', OLD.chronolog_owner);
      UPDATE notes SET body = 'must fail' WHERE id = OLD.id;
    END`)
    await book.expectOutcome('policy:notes:update', BOB, 'DELETE FROM notes WHERE id = 1')
    expect(rows(book.materializer, 'SELECT body FROM notes WHERE id = 1')).toEqual([['another replacement']])
  })

  it('does not expose lifecycle metadata privileges to direct SQL or application triggers', async () => {
    const book = await notesLedger()
    await book.expectOutcome('denied', ALICE, 'UPDATE chronolog_grants SET revoked_tx = NULL')
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TRIGGER resurrect_grants AFTER UPDATE ON notes BEGIN UPDATE chronolog_grants SET revoked_tx = NULL; END')
    await book.expectOutcome('denied', ALICE, "UPDATE notes SET body = 'trigger' WHERE id = 1")
    await book.expectOutcome('accepted', ROOT_KEY, 'DROP TRIGGER resurrect_grants',
      "CREATE TRIGGER forge_offer AFTER UPDATE ON notes BEGIN UPDATE chronolog_transfers SET state = 'open'; END")
    await book.expectOutcome('denied', ALICE, "UPDATE notes SET body = 'trigger' WHERE id = 1")
  })

  it('limits grantees to the granted operations, rows and columns, and revocation applies in order', async () => {
    const book = await notesLedger()
    const grantTx = await book.expectOutcome('accepted', ALICE,
      platformOp.grant({ table: 'notes', grantee: BOB, operations: ['update'], rowKey: [1n], columns: ['status'] }))
    await book.expectOutcome('accepted', BOB, "UPDATE notes SET status = 'reviewed' WHERE id = 1")
    await book.expectOutcome('policy:notes:update', BOB, "UPDATE notes SET body = 'x' WHERE id = 1")
    await book.expectOutcome('policy:notes:update', BOB, "UPDATE notes SET status = 'reviewed' WHERE id = 2")
    await book.expectOutcome('policy:notes:delete', BOB, 'DELETE FROM notes WHERE id = 1')
    const grantId = await platformObjectId(grantTx, 0)
    await book.expectOutcome('platform:not_owner', CAROL, platformOp.revokeGrant(grantId))
    await book.expectOutcome('accepted', ALICE, platformOp.revokeGrant(grantId))
    await book.expectOutcome('policy:notes:update', BOB, "UPDATE notes SET status = 'again' WHERE id = 1")
    await book.expectOutcome('platform:grant_revoked', ALICE, platformOp.revokeGrant(grantId))
  })

  it('grants whole-table insert, update and delete on the grantor\'s rows only', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ALICE, platformOp.grant({ table: 'notes', grantee: BOB, operations: ['insert', 'update', 'delete'] }))
    await book.expectOutcome('accepted', BOB, sqlStatement("INSERT INTO notes (id, body, chronolog_owner) VALUES (3, 'for alice', (SELECT id FROM chronolog_principals WHERE key = ?))", [ALICE]))
    await book.expectOutcome('accepted', BOB, "UPDATE notes SET body = 'by bob' WHERE id = 2")
    await book.expectOutcome('accepted', BOB, 'DELETE FROM notes WHERE id = 1')
    await book.expectOutcome('policy:notes:update', CAROL, "UPDATE notes SET body = 'carol' WHERE id = 2")
    await book.expectOutcome('platform:not_owner', BOB, platformOp.grant({ table: 'notes', grantee: CAROL, operations: ['update'], grantor: ALICE }))
    await book.expectOutcome('platform:invalid_grant', ALICE, platformOp.grant({ table: 'notes', grantee: BOB, operations: ['insert'], rowKey: [2n] }))
    await book.expectOutcome('platform:unknown_column', ALICE, platformOp.grant({ table: 'notes', grantee: BOB, operations: ['update'], columns: ['nope'] }))
    await book.expectOutcome('platform:not_owner', ALICE, platformOp.grant({ table: 'notes', grantee: CAROL, operations: ['update'], rowKey: [10n] }))
    expect(rows(book.materializer, 'SELECT id, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM notes ORDER BY id')).toEqual([['2', hex(ALICE)], ['3', hex(ALICE)], ['10', hex(BOB)]])
  })
})

describe('owner-controlled rows: collectives', () => {
  it('enforces collective governance and membership acceptance', async () => {
    const book = await notesLedger()
    const created = await book.expectOutcome('accepted', ALICE,
      platformOp.createCollective({ governance: { insert: 'member', update: 'member', delete: 'admin' }, invitees: [BOB] }))
    const team = await platformObjectId(created, 0)
    // Invited but not yet a member.
    await book.expectOutcome('policy:notes:insert', BOB, sqlStatement("INSERT INTO notes (id, body, chronolog_owner) VALUES (20, 'team', (SELECT id FROM chronolog_principals WHERE key = ?))", [team]))
    await book.expectOutcome('platform:not_invited', CAROL, platformOp.acceptMembership(team))
    await book.expectOutcome('accepted', BOB, platformOp.acceptMembership(team))
    await book.expectOutcome('accepted', BOB, sqlStatement("INSERT INTO notes (id, body, chronolog_owner) VALUES (20, 'team', (SELECT id FROM chronolog_principals WHERE key = ?))", [team]))
    await book.expectOutcome('accepted', ALICE, "UPDATE notes SET body = 'edited by alice' WHERE id = 20")
    await book.expectOutcome('policy:notes:delete', BOB, 'DELETE FROM notes WHERE id = 20')
    await book.expectOutcome('platform:not_collective_admin', BOB, platformOp.setMembers(team, [{ member: CAROL, role: 'member' }]))
    await book.expectOutcome('platform:last_admin', ALICE, platformOp.leave(team))
    await book.expectOutcome('accepted', ALICE, platformOp.setMembers(team, [{ member: BOB, role: 'admin' }]))
    await book.expectOutcome('accepted', BOB, 'DELETE FROM notes WHERE id = 20')
    await book.expectOutcome('accepted', BOB, platformOp.setMembers(team, [{ member: ALICE, role: 'remove' }]))
    await book.expectOutcome('policy:notes:insert', ALICE, sqlStatement("INSERT INTO notes (id, body, chronolog_owner) VALUES (21, 'x', (SELECT id FROM chronolog_principals WHERE key = ?))", [team]))
  })

  it('keeps group administration independent of object DDL ownership', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ROOT_KEY, platformOp.setMembers(GROUP_COLLECTIVE_ID, [{ member: ALICE, role: 'admin' }]))
    await book.expectOutcome('denied', ALICE, 'CREATE INDEX notes_status ON notes (status)')
    await book.expectOutcome('denied', ALICE, platformOp.acceptMembership(GROUP_COLLECTIVE_ID), 'CREATE INDEX notes_status ON notes (status)')
    await book.expectOutcome('accepted', ALICE, platformOp.acceptMembership(GROUP_COLLECTIVE_ID))
    await book.expectOutcome('accepted', ROOT_KEY, platformOp.grantDdl({ scope: { kind: 'object', name: 'notes' }, grantee: ALICE, operations: ['index'] }))
    await book.expectOutcome('accepted', ALICE, 'CREATE INDEX notes_status ON notes (status)')
    await book.expectOutcome('accepted', ALICE, platformOp.setMembers(GROUP_COLLECTIVE_ID, [{ member: ROOT_KEY, role: 'remove' }]))
    await book.expectOutcome('accepted', ROOT_KEY, 'DROP INDEX notes_status')
  })
})

describe('owner-controlled rows: transfer', () => {
  it('finds dependents using parent FK collation and affinity, excluding NULL references', async () => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE parents (id INTEGER PRIMARY KEY, code TEXT COLLATE NOCASE, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), UNIQUE(code, chronolog_owner))',
      'CREATE TABLE children (id INTEGER PRIMARY KEY, code TEXT COLLATE BINARY, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), FOREIGN KEY(code, chronolog_owner) REFERENCES parents(code, chronolog_owner) ON UPDATE CASCADE)')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO parents (id, code) VALUES (1, 'A'), (2, NULL)",
      "INSERT INTO children (id, code) VALUES (1, 'a'), (2, NULL)")
    const carry = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'parents', rowKey: [1n], toOwner: BOB, carry: true }))
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(await platformObjectId(carry, 0)))
    expect(rows(book.materializer, 'SELECT id, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM children ORDER BY id'))
      .toEqual([['1', hex(BOB)], ['2', hex(ALICE)]])
    // The NULL child is not a reference to the NULL-valued parent.
    const noReference = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'parents', rowKey: [2n], toOwner: BOB }))
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(await platformObjectId(noReference, 0)))

    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE exact_parents (id INTEGER PRIMARY KEY, code TEXT COLLATE BINARY NOT NULL, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), UNIQUE(code, chronolog_owner))',
      'CREATE TABLE case_children (id INTEGER PRIMARY KEY, code TEXT COLLATE NOCASE, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), FOREIGN KEY(code, chronolog_owner) REFERENCES exact_parents(code, chronolog_owner) ON UPDATE CASCADE)',
      'CREATE TABLE numeric_children (id INTEGER PRIMARY KEY, code INTEGER, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), FOREIGN KEY(code, chronolog_owner) REFERENCES exact_parents(code, chronolog_owner) ON UPDATE CASCADE)')
    await book.expectOutcome('accepted', ALICE,
      "INSERT INTO exact_parents (id, code) VALUES (1, 'a'), (2, 'A'), (3, '1'), (4, '01')",
      "INSERT INTO case_children (id, code) VALUES (1, 'a')", 'INSERT INTO numeric_children (id, code) VALUES (1, 1)')
    // 'A' has no dependent despite the child's NOCASE collation.
    const upper = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'exact_parents', rowKey: [2n], toOwner: BOB }))
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(await platformObjectId(upper, 0)))
    // Parent TEXT '01' has no FK reference from INTEGER 1. SQLite's generated
    // cascade nevertheless attempts to change that numeric child. Do not
    // broaden transfer exemptions to compensate: reject and roll back.
    const numeric = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'exact_parents', rowKey: [4n], toOwner: BOB }))
    await book.expectOutcome('policy:numeric_children:update', BOB, platformOp.acceptTransfer(await platformObjectId(numeric, 0)))
    expect(rows(book.materializer, 'SELECT hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM case_children'))
      .toEqual([[hex(ALICE)]])
    expect(rows(book.materializer, 'SELECT hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM numeric_children'))
      .toEqual([[hex(ALICE)]])
  })

  it('lets either endpoint cancel, rejects other callers, and never revives cancelled offers', async () => {
    const book = await notesLedger()
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'notes', rowKey: [1n], toOwner: BOB }))
    const id = await platformObjectId(offer, 0)
    await book.expectOutcome('platform:not_owner', CAROL, platformOp.cancelTransfer(id))
    await book.expectOutcome('accepted', ALICE, platformOp.cancelTransfer(id))
    await book.expectOutcome('platform:offer_closed', BOB, platformOp.acceptTransfer(id))
    const declined = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'notes', rowKey: [1n], toOwner: BOB }))
    await book.expectOutcome('accepted', BOB, platformOp.cancelTransfer(await platformObjectId(declined, 0)))
  })

  it('closes offers on content changes, delete/recreate, and ownership ABA', async () => {
    const book = await notesLedger()
    const changed = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'notes', rowKey: [1n], toOwner: BOB }))
    await book.expectOutcome('accepted', ALICE, "UPDATE notes SET body = 'changed' WHERE id = 1")
    await book.expectOutcome('platform:offer_closed', BOB, platformOp.acceptTransfer(await platformObjectId(changed, 0)))
    const deleted = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'notes', rowKey: [1n], toOwner: BOB }))
    await book.expectOutcome('accepted', ALICE, 'DELETE FROM notes WHERE id = 1', "INSERT INTO notes (id, body) VALUES (1, 'changed')")
    await book.expectOutcome('platform:offer_closed', BOB, platformOp.acceptTransfer(await platformObjectId(deleted, 0)))
    const oldOffer = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'notes', rowKey: [1n], toOwner: BOB }))
    const toCarol = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'notes', rowKey: [1n], toOwner: CAROL }))
    await book.expectOutcome('accepted', CAROL, platformOp.acceptTransfer(await platformObjectId(toCarol, 0)))
    const back = await book.expectOutcome('accepted', CAROL, platformOp.transferRow({ table: 'notes', rowKey: [1n], toOwner: ALICE }))
    await book.expectOutcome('accepted', ALICE, platformOp.acceptTransfer(await platformObjectId(back, 0)))
    await book.expectOutcome('platform:offer_closed', BOB, platformOp.acceptTransfer(await platformObjectId(oldOffer, 0)))
  })

  it('binds bulk offers to the offered snapshot and carry offers to their dependent set', async () => {
    const book = await notesLedger()
    const all = await book.expectOutcome('accepted', ALICE, platformOp.transferAll({ toOwner: BOB }))
    await book.expectOutcome('accepted', ALICE, "INSERT INTO notes (id, body) VALUES (3, 'acquired later')")
    await book.expectOutcome('platform:offer_closed', BOB, platformOp.acceptTransfer(await platformObjectId(all, 0)))
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE parents (id INTEGER PRIMARY KEY, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), UNIQUE (id, chronolog_owner))',
      'CREATE TABLE children (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), FOREIGN KEY (parent_id, chronolog_owner) REFERENCES parents (id, chronolog_owner) ON UPDATE CASCADE ON DELETE CASCADE)')
    await book.expectOutcome('accepted', ALICE, 'INSERT INTO parents(id) VALUES (1)', 'INSERT INTO children(id,parent_id) VALUES (1,1)')
    const carry = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'parents', rowKey: [1n], toOwner: BOB, carry: true }))
    await book.expectOutcome('accepted', ALICE, 'INSERT INTO children(id,parent_id) VALUES (2,1)')
    await book.expectOutcome('platform:offer_stale', BOB, platformOp.acceptTransfer(await platformObjectId(carry, 0)))
    const fresh = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'parents', rowKey: [1n], toOwner: BOB, carry: true }))
    await book.expectOutcome('accepted', ALICE, 'DELETE FROM children WHERE id = 1', 'INSERT INTO children(id,parent_id) VALUES (1,1)')
    await book.expectOutcome('platform:offer_closed', BOB, platformOp.acceptTransfer(await platformObjectId(fresh, 0)))
  })

  it('does not widen a bulk transfer to rows inserted by an application trigger during acceptance', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE tags (id INTEGER PRIMARY KEY, body TEXT)')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO tags (id, body) VALUES (1, 'offered')",
      platformOp.grant({ table: 'tags', grantee: BOB, operations: ['insert'] }))
    await book.expectOutcome('accepted', ROOT_KEY, `CREATE TRIGGER add_during_move AFTER UPDATE OF chronolog_owner ON notes WHEN OLD.id = 1 BEGIN
      INSERT INTO tags (id, body, chronolog_owner) VALUES (2, 'not offered', OLD.chronolog_owner);
    END`)
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferAll({ toOwner: BOB }))
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(await platformObjectId(offer, 0)))
    expect(rows(book.materializer, 'SELECT id, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM tags ORDER BY id'))
      .toEqual([['1', hex(BOB)], ['2', hex(ALICE)]])
  })

  it('needs the recipient to accept, carries owner-composite dependents and gives app triggers no extra rights', async () => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE parents (id INTEGER PRIMARY KEY, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), UNIQUE (id, chronolog_owner))',
      `CREATE TABLE children (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()),
         FOREIGN KEY (parent_id, chronolog_owner) REFERENCES parents (id, chronolog_owner) ON UPDATE CASCADE ON DELETE CASCADE)`)
    await book.expectOutcome('accepted', ALICE, 'INSERT INTO parents (id) VALUES (1), (2)', 'INSERT INTO children (id, parent_id) VALUES (1, 1), (2, 1)')
    await book.expectOutcome('accepted', CAROL, 'INSERT INTO parents (id) VALUES (3)')
    await book.expectOutcome('platform:not_owner', BOB, platformOp.transferRow({ table: 'parents', rowKey: [1n], toOwner: BOB }))
    const plain = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'parents', rowKey: [1n], toOwner: BOB }))
    await book.expectOutcome('platform:has_dependents', BOB, platformOp.acceptTransfer(await platformObjectId(plain, 0)))
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'parents', rowKey: [1n], toOwner: BOB, carry: true }))
    const offerId = await platformObjectId(offer, 0)
    await book.expectOutcome('platform:not_recipient', CAROL, platformOp.acceptTransfer(offerId))
    // An app trigger firing during the transfer still writes as the signer (Bob): it cannot touch Carol's row.
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TRIGGER parents_moved AFTER UPDATE OF chronolog_owner ON parents BEGIN UPDATE parents SET id = id WHERE id = 3; END')
    await book.expectOutcome('policy:parents:update', BOB, platformOp.acceptTransfer(offerId))
    await book.expectOutcome('accepted', ROOT_KEY, 'DROP TRIGGER parents_moved')
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(offerId))
    await book.expectOutcome('platform:offer_closed', BOB, platformOp.acceptTransfer(offerId))
    expect(rows(book.materializer, `
      SELECT 'p' || id, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM parents UNION ALL SELECT 'c' || id, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM children ORDER BY 1
    `)).toEqual([['c1', hex(BOB)], ['c2', hex(BOB)], ['p1', hex(BOB)], ['p2', hex(ALICE)], ['p3', hex(CAROL)]])
    await book.expectOutcome('policy:parents:update', ALICE, 'UPDATE parents SET id = 9 WHERE id = 1')
    await book.expectOutcome('accepted', BOB, 'DELETE FROM parents WHERE id = 1')
  })

  it('moves every row of the old key in a bulk key-change transfer', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE tags (id INTEGER PRIMARY KEY, tag TEXT)')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO tags (id, tag) VALUES (1, 'a')",
      platformOp.grant({ table: 'notes', grantee: CAROL, operations: ['update'] }))
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferAll({ toOwner: CAROL }))
    await book.expectOutcome('accepted', CAROL, platformOp.acceptTransfer(await platformObjectId(offer, 0)))
    expect(rows(book.materializer, `
      SELECT hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)), count(*) FROM (SELECT chronolog_owner FROM notes UNION ALL SELECT chronolog_owner FROM tags)
       GROUP BY 1 ORDER BY 1
    `)).toEqual([[hex(BOB), '1'], [hex(CAROL), '3']].sort((left, right) => String(left[0]).localeCompare(String(right[0]))))
    await book.expectOutcome('policy:notes:update', ALICE, "UPDATE notes SET body = 'old key' WHERE id = 1")
    expect(rows(book.materializer, 'SELECT hex(grantor) FROM chronolog_grants')).toEqual([[hex(CAROL)]])
  })
})

describe('owner-controlled rows: transfer acceptance row generations', () => {
  it.each(['DELETE then INSERT', 'REPLACE'])('rejects same-key, same-content recreation of a later bulk-transfer row with %s', async (replacement) => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE tags (id INTEGER PRIMARY KEY, body TEXT)')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO tags (id, body) VALUES (1, 'offered')",
      platformOp.grant({ table: 'tags', grantee: BOB, operations: ['insert', 'delete'] }))
    await book.expectOutcome('accepted', ROOT_KEY, `CREATE TRIGGER replace_during_move AFTER UPDATE OF chronolog_owner ON notes
      WHEN OLD.id = 1 AND OLD.chronolog_owner IS NOT NEW.chronolog_owner BEGIN
        ${replacement === 'REPLACE' ? 'REPLACE' : 'DELETE FROM tags WHERE id = 1; INSERT'}
          INTO tags (id, body, chronolog_owner) VALUES (1, 'offered', OLD.chronolog_owner);
      END`)
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferAll({ toOwner: BOB }))
    const offerId = await platformObjectId(offer, 0)
    await book.expectOutcome(replacement === 'REPLACE' ? 'policy:tags:insert' : 'policy:tags:delete', BOB, platformOp.acceptTransfer(offerId))
    expect(rows(book.materializer, 'SELECT body, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM tags'))
      .toEqual([['offered', hex(ALICE)]])
    expect(rows(book.materializer, 'SELECT state FROM chronolog_transfers')).toEqual([['open']])
    // A rejected acceptance rolls back every row and guard; removing the app
    // trigger permits a fresh acceptance of the unchanged original snapshot.
    await book.expectOutcome('accepted', ROOT_KEY, 'DROP TRIGGER replace_during_move')
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(offerId))
    expect(rows(book.materializer, 'SELECT count(*) FROM chronolog_exemptions')).toEqual([['0']])
  })

  it('rejects a carried dependent replaced by a BEFORE owner-change trigger', async () => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE parents (id INTEGER PRIMARY KEY, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), UNIQUE(id, chronolog_owner))',
      'CREATE TABLE children (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL, body TEXT, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), FOREIGN KEY(parent_id, chronolog_owner) REFERENCES parents(id, chronolog_owner) ON UPDATE CASCADE)')
    await book.expectOutcome('accepted', ALICE, 'INSERT INTO parents(id) VALUES(1)', "INSERT INTO children(id,parent_id,body) VALUES(1,1,'offered')",
      platformOp.grant({ table: 'children', grantee: BOB, operations: ['insert', 'delete'] }))
    await book.expectOutcome('accepted', ROOT_KEY, `CREATE TRIGGER replace_child BEFORE UPDATE OF chronolog_owner ON parents
      WHEN OLD.chronolog_owner IS NOT NEW.chronolog_owner BEGIN
        DELETE FROM children WHERE id = 1;
        INSERT INTO children (id, parent_id, body, chronolog_owner) VALUES (1, 1, 'offered', OLD.chronolog_owner);
      END`)
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'parents', rowKey: [1n], toOwner: BOB, carry: true }))
    await book.expectOutcome('policy:children:delete', BOB, platformOp.acceptTransfer(await platformObjectId(offer, 0)))
    expect(rows(book.materializer, 'SELECT hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM children'))
      .toEqual([[hex(ALICE)]])
  })

  it.each([
    ['61006F6E65', 'chronolog_owner'],
    ['80FF00C3', 'CHRONOLOG_OWNER'],
  ])('protects an owner-composite destination with raw TEXT %s, a REAL key and a %s PK reference', async (idHex, ownerColumn) => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      `CREATE TABLE entries (id TEXT NOT NULL, stamp REAL NOT NULL, body TEXT, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), PRIMARY KEY(id, stamp, ${ownerColumn})) WITHOUT ROWID`)
    await book.expectOutcome('accepted', ALICE, `INSERT INTO entries(id,stamp,body) VALUES(CAST(X'${idHex}' AS TEXT),1.0000000000000002,'offered')`)
    await book.expectOutcome('accepted', ROOT_KEY, `CREATE TRIGGER replace_received AFTER UPDATE OF chronolog_owner ON entries
      WHEN OLD.chronolog_owner IS NOT NEW.chronolog_owner BEGIN
        DELETE FROM entries WHERE id = NEW.id AND stamp = NEW.stamp AND chronolog_owner = NEW.chronolog_owner;
        INSERT INTO entries (id, stamp, body, chronolog_owner) VALUES (NEW.id, NEW.stamp, NEW.body, NEW.chronolog_owner);
      END`)
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferAll({ toOwner: BOB }))
    const offerId = await platformObjectId(offer, 0)
    await book.expectOutcome('policy:entries:delete', BOB, platformOp.acceptTransfer(offerId))
    await book.expectOutcome('accepted', ROOT_KEY, 'DROP TRIGGER replace_received')
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(offerId))
    expect(rows(book.materializer, 'SELECT hex(id), typeof(stamp), chronolog_value_equal(stamp, 1.0000000000000002), hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM entries'))
      .toEqual([[idHex, 'real', '1', hex(BOB)]])
  })

  it('rejects re-keying a captured row away and back during bulk acceptance', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE tags (id INTEGER PRIMARY KEY, body TEXT)')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO tags(id,body) VALUES(1,'offered')",
      platformOp.grant({ table: 'tags', grantee: BOB, operations: ['update'] }))
    await book.expectOutcome('accepted', ROOT_KEY, `CREATE TRIGGER rekey_during_move AFTER UPDATE OF chronolog_owner ON notes
      WHEN OLD.id = 1 AND OLD.chronolog_owner IS NOT NEW.chronolog_owner BEGIN
        UPDATE tags SET id = 99 WHERE id = 1;
        UPDATE tags SET id = 1 WHERE id = 99;
      END`)
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferAll({ toOwner: BOB }))
    await book.expectOutcome('policy:tags:update', BOB, platformOp.acceptTransfer(await platformObjectId(offer, 0)))
    expect(rows(book.materializer, 'SELECT id, body FROM tags')).toEqual([['1', 'offered']])
  })

  it.each([
    ['owner-composite primary key', 'PRIMARY KEY(id, chronolog_owner) ON CONFLICT IGNORE', 1],
    ['non-key unique owner', 'PRIMARY KEY(id), UNIQUE(chronolog_owner) ON CONFLICT IGNORE', 2],
  ] as const)('rejects a bulk owner change silently skipped by an existing %s conflict', async (name, constraints, bobId) => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      `CREATE TABLE entries (id INTEGER NOT NULL, body TEXT, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), ${constraints}) WITHOUT ROWID`)
    await book.expectOutcome('accepted', ALICE, "INSERT INTO entries(id,body) VALUES(1,'offered')")
    await book.expectOutcome('accepted', BOB, `INSERT INTO entries(id,body) VALUES(${bobId},'existing')`)
    const ownerId = BigInt(String(rows(book.materializer, "SELECT chronolog_owner FROM entries WHERE body = 'offered'")[0]![0]))
    await book.expectOutcome('accepted', ALICE, sealedOp.readerPolicy({ table: 'entries',
      rowKey: name === 'owner-composite primary key' ? [1n, ownerId] : [1n], expectedVersion: 0n, readers: [] }))
    const policyBefore = rows(book.materializer, 'SELECT hex(policy_id), row_key, version, closed_tx FROM chronolog_reader_policies')
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferAll({ toOwner: BOB }))
    const offerId = await platformObjectId(offer, 0)
    await book.expectOutcome('platform:offer_stale', BOB, platformOp.acceptTransfer(offerId))
    expect(rows(book.materializer, 'SELECT body, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM entries ORDER BY body'))
      .toEqual([['existing', hex(BOB)], ['offered', hex(ALICE)]])
    expect(rows(book.materializer, 'SELECT state FROM chronolog_transfers')).toEqual([['open']])
    expect(rows(book.materializer, 'SELECT hex(policy_id), row_key, version, closed_tx FROM chronolog_reader_policies')).toEqual(policyBefore)
    // A rolled-back conflict leaves the original snapshot available. Removing
    // the recipient's unrelated row makes the same offer transferable.
    await book.expectOutcome('accepted', BOB, "DELETE FROM entries WHERE body = 'existing'")
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(offerId))
    expect(rows(book.materializer, 'SELECT body, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM entries'))
      .toEqual([['offered', hex(BOB)]])
  })

  it.each(['insert', 'update'] as const)('rejects a BEFORE-trigger %s into a reserved destination', async (operation) => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE entries (id INTEGER NOT NULL, body TEXT, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), PRIMARY KEY(id, chronolog_owner) ON CONFLICT IGNORE) WITHOUT ROWID')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO entries(id,body) VALUES(1,'offered')")
    if (operation === 'update') await book.expectOutcome('accepted', BOB, "INSERT INTO entries(id,body) VALUES(2,'existing')")
    await book.expectOutcome('accepted', ROOT_KEY, `CREATE TRIGGER fill_destination BEFORE UPDATE OF chronolog_owner ON entries
      WHEN OLD.chronolog_owner IS NOT NEW.chronolog_owner BEGIN
        ${operation === 'insert'
          ? 'INSERT INTO entries(id,body,chronolog_owner) VALUES(OLD.id,OLD.body,NEW.chronolog_owner);'
          : 'UPDATE entries SET id = OLD.id WHERE id = 2 AND chronolog_owner = NEW.chronolog_owner;'}
      END`)
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferAll({ toOwner: BOB }))
    await book.expectOutcome(`policy:entries:${operation}`, BOB, platformOp.acceptTransfer(await platformObjectId(offer, 0)))
    expect(rows(book.materializer, 'SELECT state FROM chronolog_transfers')).toEqual([['open']])
    expect(rows(book.materializer, 'SELECT id, body FROM entries ORDER BY id'))
      .toEqual(operation === 'insert' ? [['1', 'offered']] : [['1', 'offered'], ['2', 'existing']])
  })

  it.each(['insert', 'update'] as const)('rejects an AFTER-trigger %s into the vacated source identity', async (operation) => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE entries (id INTEGER NOT NULL, body TEXT, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), PRIMARY KEY(id, chronolog_owner)) WITHOUT ROWID')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO entries(id,body) VALUES(1,'offered'),(2,'unoffered')",
      platformOp.grant({ table: 'entries', grantee: BOB, operations: [operation] }))
    await book.expectOutcome('accepted', ROOT_KEY, `CREATE TRIGGER fill_source AFTER UPDATE OF chronolog_owner ON entries
      WHEN OLD.chronolog_owner IS NOT NEW.chronolog_owner BEGIN
        ${operation === 'insert'
          ? 'INSERT INTO entries(id,body,chronolog_owner) VALUES(OLD.id,OLD.body,OLD.chronolog_owner);'
          : 'UPDATE entries SET id = OLD.id WHERE id = 2 AND chronolog_owner = OLD.chronolog_owner;'}
      END`)
    const ownerId = BigInt(String(rows(book.materializer, 'SELECT chronolog_owner FROM entries WHERE id = 1')[0]![0]))
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferRow({ table: 'entries', rowKey: [1n, ownerId], toOwner: BOB }))
    await book.expectOutcome(`policy:entries:${operation}`, BOB, platformOp.acceptTransfer(await platformObjectId(offer, 0)))
    expect(rows(book.materializer, 'SELECT id, body, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM entries ORDER BY id'))
      .toEqual([['1', 'offered', hex(ALICE)], ['2', 'unoffered', hex(ALICE)]])
  })

  it('preserves unrelated application-trigger INSERT OR IGNORE behavior during acceptance', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE audit (id INTEGER PRIMARY KEY, body TEXT)')
    await book.expectOutcome('accepted', BOB, "INSERT INTO audit(id,body) VALUES(1,'existing')")
    await book.expectOutcome('accepted', ROOT_KEY, `CREATE TRIGGER record_move AFTER UPDATE OF chronolog_owner ON notes BEGIN
      INSERT OR IGNORE INTO audit(id,body) VALUES(1,'duplicate');
    END`)
    const offer = await book.expectOutcome('accepted', ALICE, platformOp.transferAll({ toOwner: BOB }))
    await book.expectOutcome('accepted', BOB, platformOp.acceptTransfer(await platformObjectId(offer, 0)))
    expect(rows(book.materializer, 'SELECT body FROM audit')).toEqual([['existing']])
    expect(rows(book.materializer, 'SELECT count(*) FROM notes WHERE chronolog_owner = (SELECT id FROM chronolog_principals WHERE key = ?)', [{ kind: 'blob', value: BOB }]))
      .toEqual([['3']])
  })
})

describe('owner-controlled rows: fork seeding', () => {
  it('never lets the root seed rows or grants in a group that is not a fork', async () => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)')
    await book.expectOutcome('platform:seed_closed', ROOT_KEY, platformOp.seedRows('notes', ['id', 'body', 'chronolog_owner'], [[2n, 'x', BOB]]))
    await book.expectOutcome('platform:seed_closed', ROOT_KEY, platformOp.seedRows('chronolog_grants',
      ['grant_id', 'tbl', 'grantor', 'grantee_key', 'row_key', 'op_insert', 'op_update', 'op_delete', 'columns', 'created_tx', 'revoked_tx'],
      [[testKey(0x55), 'notes', BOB, ROOT_KEY, null, 0n, 1n, 0n, null, testKey(0x56), null]]))
    expect(rows(book.materializer, 'SELECT count(*) FROM notes')).toEqual([['0']])
  })

  it('lets only the genesis root of a fork seed verbatim owners, before anyone else writes', async () => {
    const book = await ledger({ forkSeeding: true })
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)')
    await book.expectOutcome('platform:not_root', ALICE, platformOp.seedRows('notes', ['id', 'body', 'chronolog_owner'], [[1n, 'x', ALICE]]))
    await book.expectOutcome('platform:invalid_seed', ROOT_KEY, platformOp.seedRows('notes', ['id', 'body'], [[1n, 'x']]))
    await book.expectOutcome('accepted', ROOT_KEY, platformOp.seedRows('notes', ['id', 'body', 'chronolog_owner'], [[1n, 'alice', ALICE], [2n, 'bob', BOB]]))
    expect(rows(book.materializer, 'SELECT id, hex((SELECT key FROM chronolog_principals WHERE id = chronolog_owner)) FROM notes ORDER BY id')).toEqual([['1', hex(ALICE)], ['2', hex(BOB)]])
    expect(rows(book.materializer, 'SELECT count(*) FROM chronolog_exemptions')).toEqual([['0']])
    await book.expectOutcome('accepted', ALICE, "UPDATE notes SET body = 'mine' WHERE id = 1")
    await book.expectOutcome('platform:seed_closed', ROOT_KEY, platformOp.seedRows('notes', ['id', 'body', 'chronolog_owner'], [[3n, 'late', BOB]]))
  })

  it('lets the fork root end seeding itself, before anyone else writes', async () => {
    const book = await ledger({ forkSeeding: true })
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)')
    await book.expectOutcome('platform:not_root', ALICE, platformOp.endSeeding())
    await book.expectOutcome('accepted', ROOT_KEY, platformOp.seedRows('notes', ['id', 'body', 'chronolog_owner'], [[1n, 'alice', ALICE]]))
    await book.expectOutcome('accepted', ROOT_KEY, platformOp.endSeeding())
    await book.expectOutcome('platform:seed_closed', ROOT_KEY, platformOp.seedRows('notes', ['id', 'body', 'chronolog_owner'], [[2n, 'forged', BOB]]))
    await book.expectOutcome('platform:seed_closed', ROOT_KEY, platformOp.endSeeding())
    expect(rows(book.materializer, 'SELECT id FROM notes ORDER BY id')).toEqual([['1']])
  })
})

describe('owner-controlled rows: virtual tables', () => {
  it('keeps FTS5 and vec0 indexes in sync through app triggers and refuses direct writes to them', async () => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, embedding TEXT NOT NULL)',
      'CREATE VIRTUAL TABLE notes_fts USING fts5(body)',
      'CREATE VIRTUAL TABLE notes_vec USING vec0(e float[2])',
      'CREATE VIRTUAL TABLE notes_box USING rtree(id, x0, x1)',
      `CREATE TRIGGER notes_index AFTER INSERT ON notes BEGIN
         INSERT INTO notes_fts (rowid, body) VALUES (NEW.id, NEW.body);
         INSERT INTO notes_vec (rowid, e) VALUES (NEW.id, NEW.embedding);
         INSERT INTO notes_box VALUES (NEW.id, 0, NEW.id);
       END`,
      `CREATE TRIGGER notes_unindex AFTER DELETE ON notes BEGIN
         DELETE FROM notes_fts WHERE rowid = OLD.id;
         DELETE FROM notes_vec WHERE rowid = OLD.id;
         DELETE FROM notes_box WHERE id = OLD.id;
       END`)
    await book.expectOutcome('accepted', ALICE, "INSERT INTO notes (id, body, embedding) VALUES (1, 'hello alice', '[1, 0]')")
    await book.expectOutcome('accepted', BOB, "INSERT INTO notes (id, body, embedding) VALUES (2, 'hello bob', '[0, 1]')")
    expect(rows(book.materializer, "SELECT rowid FROM notes_fts WHERE notes_fts MATCH 'hello' ORDER BY rowid")).toEqual([['1'], ['2']])
    expect(rows(book.materializer, "SELECT rowid FROM notes_vec WHERE e MATCH '[1, 0]' AND k = 1")).toEqual([['1']])

    // Nothing writes an index directly, owner or not.
    await book.expectOutcome('denied', BOB, 'DELETE FROM notes_fts WHERE rowid = 1')
    await book.expectOutcome('denied', ALICE, "INSERT INTO notes_fts (rowid, body) VALUES (9, 'forged')")
    await book.expectOutcome('denied', BOB, 'DELETE FROM notes_vec WHERE rowid = 1')
    await book.expectOutcome('denied', BOB, 'DELETE FROM notes_vec_vector_chunks00')
    await book.expectOutcome('denied', BOB, 'DELETE FROM notes_box WHERE id = 1')
    // Not even a schema administrator.
    await book.expectOutcome('denied', ROOT_KEY, 'DELETE FROM notes_fts')
    // The modules' internal pragmas stay out of reach of app SQL.
    await book.expectOutcome('denied', ALICE, 'PRAGMA data_version')
    await book.expectOutcome('denied', ALICE, 'SELECT * FROM pragma_data_version')
    await book.expectOutcome('denied', ALICE, 'SELECT * FROM "PRAGMA_DATA_VERSION"')
    await book.expectOutcome('denied', ALICE, 'PRAGMA main.page_size')
    await book.expectOutcome('denied', ROOT_KEY, 'CREATE VIEW dv AS SELECT * FROM pragma_data_version')

    // Deleting a row is owner-checked, and its trigger keeps the indexes in sync.
    await book.expectOutcome('policy:notes:delete', BOB, 'DELETE FROM notes WHERE id = 1')
    await book.expectOutcome('accepted', ALICE, 'DELETE FROM notes WHERE id = 1')
    expect(rows(book.materializer, "SELECT rowid FROM notes_fts WHERE notes_fts MATCH 'hello'")).toEqual([['2']])
    expect(rows(book.materializer, 'SELECT rowid FROM notes_vec ORDER BY rowid')).toEqual([['2']])
    expect(rows(book.materializer, 'SELECT id FROM notes_box ORDER BY id')).toEqual([['2']])
  })

  it('treats a table named like a vec0 chunk table as an ordinary owner-checked table unless vec0 made it', async () => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY,
      'CREATE VIRTUAL TABLE v USING vec0(e float[2])',
      'CREATE TABLE "v_vector_chunks01"(rowid INTEGER PRIMARY KEY,vectors BLOB NOT NULL)',
      'CREATE TABLE "w_vector_chunks00"(rowid INTEGER PRIMARY KEY,vectors BLOB NOT NULL)')
    expect(rows(book.materializer, 'SELECT name FROM chronolog_tables ORDER BY name')).toEqual([['v_vector_chunks01'], ['w_vector_chunks00']])
  })

  it('allows AUTOINCREMENT tables', async () => {
    const book = await ledger()
    await book.expectOutcome('accepted', ROOT_KEY, 'CREATE TABLE a (id INTEGER PRIMARY KEY AUTOINCREMENT, x TEXT)')
    await book.expectOutcome('accepted', ALICE, "INSERT INTO a (x) VALUES ('one')")
    expect(rows(book.materializer, 'SELECT id, x FROM a')).toEqual([['1', 'one']])
  })
})

describe('owner-controlled rows: determinism', () => {
  it('produces the same database when replayed from scratch in one pass', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ALICE, platformOp.grant({ table: 'notes', grantee: BOB, operations: ['update'], columns: ['body'] }))
    await book.expectOutcome('accepted', BOB, "UPDATE notes SET body = 'shared' WHERE id = 1")
    await book.expectOutcome('policy:notes:update', BOB, "UPDATE notes SET status = 'x' WHERE id = 1")
    const offer = await book.expectOutcome('accepted', BOB, platformOp.transferRow({ table: 'notes', rowKey: [10n], toOwner: ALICE }))
    await book.expectOutcome('accepted', ALICE, platformOp.acceptTransfer(await platformObjectId(offer, 0)))
    const replayed = await fixtures.open()
    await replayed.materializer.materialize(book.transactions)
    expect(replayed.materializer.databaseContentHash).toBe(book.materializer.databaseContentHash)
    expect(replayed.materializer.transactionLog().map((row) => row.rejectionCode))
      .toEqual(book.materializer.transactionLog().map((row) => row.rejectionCode))
    replayed.materializer.close()
  })
})

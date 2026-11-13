import {
  GROUP_COLLECTIVE_ID,
  platformObjectId,
  platformOp,
  sqlStatement,
  type ProgramStep,
} from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import type { DeterministicMaterializer } from './materializer.js'
import { MaterializerFixture, ROOT_KEY, admitted, rows, testKey } from './test-fixtures.js'
import type { AdmittedTransaction } from './types.js'

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())

const ALICE = testKey(0x10)
const BOB = testKey(0x20)
const CAROL = testKey(0x30)

/** Appends transactions in order and reports each outcome as `accepted` or its rejection code. */
class Ledger {
  readonly #transactions: AdmittedTransaction[] = []
  #clock = 1n

  constructor(readonly materializer: DeterministicMaterializer) {}

  get transactions(): readonly AdmittedTransaction[] { return [...this.#transactions] }

  async submit(author: Uint8Array, ...steps: readonly (ProgramStep | string)[]): Promise<{ readonly outcome: string; readonly txId: Uint8Array; readonly step: number | null }> {
    const id = `tx-${this.#clock}`
    const transaction = await admitted(this.#clock, id, steps, this.materializer.executionManifestDigest, author)
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
  it('limits DDL, including triggers, to group admins', async () => {
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

  it('makes group admins schema administrators', async () => {
    const book = await notesLedger()
    await book.expectOutcome('accepted', ROOT_KEY, platformOp.setMembers(GROUP_COLLECTIVE_ID, [{ member: ALICE, role: 'admin' }]))
    await book.expectOutcome('denied', ALICE, 'CREATE INDEX notes_status ON notes (status)')
    await book.expectOutcome('accepted', ALICE, platformOp.acceptMembership(GROUP_COLLECTIVE_ID), 'CREATE INDEX notes_status ON notes (status)')
    await book.expectOutcome('accepted', ALICE, platformOp.setMembers(GROUP_COLLECTIVE_ID, [{ member: ROOT_KEY, role: 'remove' }]))
    await book.expectOutcome('denied', ROOT_KEY, 'DROP INDEX notes_status')
  })
})

describe('owner-controlled rows: transfer', () => {
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

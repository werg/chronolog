import { afterEach, describe, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { createLogGenesis } from './genesis.js'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import { createFramedPeerConnectionPair } from './network-wire.js'

const closes: Array<() => Promise<void>> = []
afterEach(async () => {
  for (const close of closes.splice(0).reverse()) {
    try { await close() } catch { /* ignore cleanup */ }
  }
})

describe('Chronolog v2 first-class chronolog/sql & pluggable $permissions', () => {
  it('runs multiple independent chronolog/sql topics with preconditions, RLS rollbacks, and user-owned dynamic DDL', async () => {
    const devAdmin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devAlice = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devBob = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

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
        { publicKey: devBob.identity.publicKey, wrapKey: devBob.wrapKey.publicKey, reader: true, writer: true },
      ],
      privateLog: true,
      topics: {
        inventory: { module: 'chronolog/sql' },
        audit: { module: 'chronolog/sql', config: { allowUserDdl: false } },
      },
    })

    const epochKeys = new Map([[0, created.epoch0Key!]])
    const sessAdmin = await createApplicationSession({
      device: devAdmin,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    const sessAlice = await createApplicationSession({
      device: devAlice,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    const sessBob = await createApplicationSession({
      device: devBob,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    closes.push(() => sessAdmin.close(), () => sessAlice.close(), () => sessBob.close())

    // 1. Admin migrates BOTH independent SQL databases + installs Postgres-style write RLS
    const migOp = await sessAdmin.submit({
      authorTimestampMs: 100n,
      updates: [
        {
          topic: 'inventory',
          input: {
            action: 'migrate',
            statements: [
              'CREATE TABLE items (id TEXT PRIMARY KEY, owner TEXT NOT NULL, qty INTEGER NOT NULL CHECK(qty >= 0))',
            ],
            policies: {
              items: {
                insert: 'NEW.owner = actor()',
                update: 'OLD.owner = actor() AND NEW.owner = actor()',
                delete: 'OLD.owner = actor()',
              },
            },
          },
        },
        {
          topic: 'audit',
          input: {
            action: 'migrate',
            statements: [
              'CREATE TABLE log (id TEXT PRIMARY KEY, actor TEXT NOT NULL, note TEXT NOT NULL)',
            ],
            policies: {
              log: { insert: 'NEW.actor = actor()' },
            },
          },
        },
      ],
    })
    expect((await migOp.materialized()).outcome).toBe('accepted')

    // Sync Admin -> Alice & Bob
    const facts1 = await sessAdmin.exportFacts()
    await sessAlice.mergeFacts(facts1)
    await sessBob.mergeFacts(facts1)

    // 2. Alice inserts her own item + audit row in one atomic multi-database op
    const addOp = await sessAlice.submit({
      authorTimestampMs: 200n,
      updates: [
        {
          topic: 'inventory',
          input: {
            statements: [{ sql: 'INSERT INTO items (id, owner, qty) VALUES (?, actor(), ?)', params: ['widget', 5] }],
            events: [{ topic: 'inventory.created', payload: { id: 'widget', qty: 5 } }],
          },
        },
        {
          topic: 'audit',
          input: {
            statements: [{ sql: 'INSERT INTO log (id, actor, note) VALUES (?, actor(), ?)', params: ['e1', 'created widget'] }],
          },
        },
      ],
    })
    expect((await addOp.materialized()).outcome).toBe('accepted')

    // 3. Alice runs a declarative SQL transaction with a PASSING precondition (qty >= 3)
    const decOk = await sessAlice.submit({
      authorTimestampMs: 300n,
      updates: [{
        topic: 'inventory',
        input: {
          preconditions: [{
            sql: 'SELECT qty >= ? FROM items WHERE id = ?',
            params: [3, 'widget'],
            code: 'insufficient_stock',
          }],
          statements: [{ sql: 'UPDATE items SET qty = qty - ? WHERE id = ?', params: [3, 'widget'] }],
        },
      }],
    })
    expect((await decOk.materialized()).outcome).toBe('accepted')

    // 4. Alice runs a transaction with a FAILING precondition (qty >= 10, only 2 left) -> atomic rollback!
    const decFail = await sessAlice.submit({
      authorTimestampMs: 400n,
      updates: [{
        topic: 'inventory',
        input: {
          preconditions: [{
            sql: 'SELECT qty >= ? FROM items WHERE id = ?',
            params: [10, 'widget'],
            code: 'insufficient_stock',
          }],
          statements: [{ sql: 'UPDATE items SET qty = qty - ? WHERE id = ?', params: [10, 'widget'] }],
        },
      }],
    })
    const decFailRes = await decFail.materialized()
    expect(decFailRes.outcome).toBe('rejected')
    expect(decFailRes.rejectionCode).toBe('insufficient_stock')

    // 5. Alice creates her own dynamic user table (allowed on inventory where allowUserDdl=true),
    //    inserts into it, and alters it; on audit (allowUserDdl=false), CREATE TABLE is denied!
    const userTableOp = await sessAlice.submit({
      authorTimestampMs: 500n,
      updates: [{
        topic: 'inventory',
        input: {
          statements: [
            'CREATE TABLE alice_notes (id TEXT PRIMARY KEY, body TEXT NOT NULL)',
            { sql: 'INSERT INTO alice_notes (id, body) VALUES (?, ?)', params: ['n1', 'hello'] },
            'ALTER TABLE alice_notes ADD COLUMN tag TEXT',
          ],
        },
      }],
    })
    expect((await userTableOp.materialized()).outcome).toBe('accepted')

    const deniedDdlOp = await sessAlice.submit({
      authorTimestampMs: 510n,
      updates: [{
        topic: 'audit',
        input: { statements: ['CREATE TABLE nope (id TEXT PRIMARY KEY)'] },
      }],
    })
    expect((await deniedDdlOp.materialized()).outcome).toBe('rejected')

    // Sync Alice -> Bob
    await sessBob.mergeFacts(await sessAlice.exportFacts())

    // 6. Bob tries to steal/update Alice's item -> rejected by RLS trigger!
    const stealOp = await sessBob.submit({
      authorTimestampMs: 600n,
      updates: [{
        topic: 'inventory',
        input: {
          statements: [{ sql: 'UPDATE items SET qty = 999 WHERE id = ?', params: ['widget'] }],
        },
      }],
    })
    const stealRes = await stealOp.materialized()
    expect(stealRes.outcome).toBe('rejected')
    expect(stealRes.rejectionCode).toBe('rls_denied:items:update')

    // 7. Bob tries to DROP Alice's user-owned table -> denied by authorizer!
    const dropAliceOp = await sessBob.submit({
      authorTimestampMs: 610n,
      updates: [{
        topic: 'inventory',
        input: { statements: ['DROP TABLE alice_notes'] },
      }],
    })
    expect((await dropAliceOp.materialized()).outcome).toBe('rejected')

    // 8. Query both independent databases + verify describe()
    const invQ = await sessBob.query('inventory', { sql: 'SELECT id, qty FROM items', format: 'objects' })
    expect(invQ.value).toEqual({ columns: ['id', 'qty'], rows: [{ id: 'widget', qty: 2 }] })

    const auditQ = await sessBob.query('audit', { sql: 'SELECT id, note FROM log', format: 'objects' })
    expect(auditQ.value).toEqual({ columns: ['id', 'note'], rows: [{ id: 'e1', note: 'created widget' }] })

    const tablesQ = await sessBob.query('inventory', { kind: 'tables' })
    expect((tablesQ.value as { tables: { name: string }[] }).tables.map(t => t.name)).toEqual(['alice_notes', 'items'])

    const desc = await sessBob.describe()
    expect(desc.commands.map(c => c.name)).toContain('inventory.exec')
    expect(desc.commands.map(c => c.name)).toContain('audit.migrate')
    expect(desc.queries.map(q => q.name)).toContain('inventory.sql')
    // Also verify dotted command/query dispatch works end-to-end
    const viaQ = await sessBob.query('inventory.sql', { sql: 'SELECT id, qty FROM items', format: 'objects' })
    expect(viaQ.value).toEqual({ columns: ['id', 'qty'], rows: [{ id: 'widget', qty: 2 }] })

    // 9. Postconditions enforce whole-transaction invariants with atomic rollback + expect.exists
    const postFail = await sessAlice.submit({
      authorTimestampMs: 700n,
      updates: [{
        topic: 'inventory',
        input: {
          preconditions: [{ sql: 'SELECT 1 FROM items WHERE id = ?', params: ['widget'], expect: { exists: true } }],
          statements: [{ sql: 'UPDATE items SET qty = 999 WHERE id = ?', params: ['widget'] }],
          postconditions: [{ sql: 'SELECT SUM(qty) <= 10 FROM items', code: 'cap_exceeded' }],
        },
      }],
    })
    expect((await postFail.materialized()).rejectionCode).toBe('cap_exceeded')
    expect((await sessAlice.query('inventory', { sql: 'SELECT qty FROM items WHERE id = ?', params: ['widget'] })).value).toEqual({
      columns: ['qty'],
      rows: [[2]],
    })

    // 10. Non-admin user creates a VIEW in op 1, Bob cannot drop it, Alice drops her own VIEW in op 2!
    const createViewOp = await sessAlice.submit({
      authorTimestampMs: 710n,
      updates: [{
        topic: 'inventory',
        input: { statements: ['CREATE VIEW alice_view AS SELECT id, qty FROM items'] },
      }],
    })
    expect((await createViewOp.materialized()).outcome).toBe('accepted')
    await sessBob.mergeFacts(await sessAlice.exportFacts())
    const bobDropView = await sessBob.submit({
      authorTimestampMs: 720n,
      updates: [{ topic: 'inventory', input: { statements: ['DROP VIEW alice_view'] } }],
    })
    expect((await bobDropView.materialized()).outcome).toBe('rejected')
    const aliceDropView = await sessAlice.submit({
      authorTimestampMs: 730n,
      updates: [{ topic: 'inventory', input: { statements: ['DROP VIEW alice_view'] } }],
    })
    expect((await aliceDropView.materialized()).outcome).toBe('accepted')

    // 11. Partial setRls merge preserves unmodified triggers on the same table!
    await sessAdmin.mergeFacts(await sessAlice.exportFacts())
    const partialRls = await sessAdmin.submit({
      authorTimestampMs: 740n,
      updates: [{
        topic: 'inventory',
        input: {
          action: 'setRls',
          policies: { items: { delete: 'OLD.owner = actor() AND OLD.qty = 0' } },
        },
      }],
    })
    expect((await partialRls.materialized()).outcome).toBe('accepted')
    await sessBob.mergeFacts(await sessAdmin.exportFacts())
    // Bob STILL cannot update Alice's item because the existing `update` trigger was preserved!
    const stillBlocked = await sessBob.submit({
      authorTimestampMs: 750n,
      updates: [{ topic: 'inventory', input: { statements: [{ sql: 'UPDATE items SET qty = 50 WHERE id = ?', params: ['widget'] }] } }],
    })
    expect((await stillBlocked.materialized()).rejectionCode).toBe('rls_denied:items:update')

    // 12. Rich `schema` introspection returns tables, columns, user owners, and active RLS policies (and caches per stateRoot)
    const schema1 = await sessBob.query('inventory', { action: 'schema' })
    const schemaVal = schema1.value as {
      readonly dbRoot: string
      readonly userOwnedObjects: Record<string, string>
      readonly tables: { readonly name: string; readonly type: string; readonly owner: string | null; readonly columns: readonly string[]; readonly rls: { readonly insert?: string | null; readonly update?: string | null; readonly delete?: string | null } | null }[]
    }
    expect(schemaVal.dbRoot).toMatch(/^[0-9a-f]{64}$/u)
    expect(schemaVal.userOwnedObjects.alice_notes).toBe(devAlice.identity.publicKey)
    const itemsMeta = schemaVal.tables.find(t => t.name === 'items')
    expect(itemsMeta).toBeDefined()
    expect(itemsMeta?.owner).toBeNull()
    expect(itemsMeta?.columns).toEqual(['id', 'owner', 'qty'])
    expect(itemsMeta?.rls?.delete).toBe('OLD.owner = actor() AND OLD.qty = 0')
    expect(itemsMeta?.rls?.update).toBe('OLD.owner = actor() AND NEW.owner = actor()')
    const aliceNotesMeta = schemaVal.tables.find(t => t.name === 'alice_notes')
    expect(aliceNotesMeta?.owner).toBe(devAlice.identity.publicKey)
    // Repeated identical query & describe return isolated defensive clones from the stateRoot cache
    const schema2 = await sessBob.query('inventory', { action: 'schema' })
    expect(schema2.value).toEqual(schema1.value)
    expect(await sessBob.describe()).toEqual(desc)
  })

  it('supports openMembers (unregistered strangers write) and multisigMembers end-to-end across ApplicationSession', async () => {
    const devCreator = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devStranger = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    // Open public SQL bulletin board — zero host attestation, strangers can write!
    const openCreated = await createLogGenesis({
      creator: { publicKey: devCreator.identity.publicKey, administrator: true, reader: true, writer: true },
      privateLog: false,
      topics: {
        $admission: {
          module: 'chronolog/admission',
          export: 'openAdmission',
          initialState: {
            admins: [devCreator.identity.publicKey],
            members: [],
            openRead: true,
            openWrite: true,
            admission: null,
          },
        },
        board: { module: 'chronolog/sql' },
      },
    })

    const sessCreator = await createApplicationSession({
      device: devCreator,
      genesis: openCreated.genesisBytes,
      casNodes: openCreated.casNodes,
    })
    const sessStranger = await createApplicationSession({
      device: devStranger,
      genesis: openCreated.genesisBytes,
      casNodes: openCreated.casNodes,
    })
    closes.push(() => sessCreator.close(), () => sessStranger.close())

    expect(sessStranger.isWriter(devStranger.identity.publicKey)).toBe(true)
    expect(sessStranger.isAdministrator(devStranger.identity.publicKey)).toBe(false)
    expect(sessStranger.status.canAuthor).toBe(true)
    expect(await sessStranger.can('writer')).toBe(true)
    expect(await sessStranger.can('administrator')).toBe(false)

    // Creator migrates board table with author-owned RLS
    const mig = await sessCreator.submit({
      authorTimestampMs: 10n,
      updates: [{
        topic: 'board',
        input: {
          action: 'migrate',
          statements: ['CREATE TABLE posts (id TEXT PRIMARY KEY, author TEXT NOT NULL, body TEXT NOT NULL)'],
          policies: { posts: { insert: 'NEW.author = actor()', update: 'OLD.author = actor()' } },
        },
      }],
    })
    expect((await mig.materialized()).outcome).toBe('accepted')

    const [p1, p2] = createFramedPeerConnectionPair()
    void sessCreator.connectPeer({ connection: p1 }).catch(() => undefined)
    void sessStranger.connectPeer({ connection: p2 }).catch(() => undefined)
    for (let i = 0; i < 60 && sessStranger.revision().orderLength < 1; i++) {
      await new Promise(r => setTimeout(r, 50))
    }
    expect(sessStranger.revision().orderLength).toBe(1)

    // Stranger (never listed in genesis!) posts to the board
    const postOp = await sessStranger.submit({
      authorTimestampMs: 20n,
      updates: [{
        topic: 'board',
        input: {
          statements: [{ sql: 'INSERT INTO posts (id, author, body) VALUES (?, actor(), ?)', params: ['p1', 'hi from stranger'] }],
        },
      }],
    })
    expect((await postOp.materialized()).outcome).toBe('accepted')

    // Stranger CANNOT run admin migrate
    const badAdmin = await sessStranger.submit({
      authorTimestampMs: 30n,
      updates: [{
        topic: 'board',
        input: { action: 'migrate', statements: ['DROP TABLE posts'] },
      }],
    })
    expect((await badAdmin.materialized()).rejectionCode).toBe('admin_required')

    // Wait for P2P sync of all 3 operations (mig + postOp + rejected badAdmin)
    for (let i = 0; i < 40 && sessCreator.revision().stateRoot !== sessStranger.revision().stateRoot; i++) {
      await new Promise(r => setTimeout(r, 50))
    }
    const q = await sessCreator.query('board', { sql: 'SELECT id, body FROM posts', format: 'objects' })
    expect(q.value).toEqual({ columns: ['id', 'body'], rows: [{ id: 'p1', body: 'hi from stranger' }] })
    expect(sessCreator.revision().stateRoot).toBe(sessStranger.revision().stateRoot)
  })
})

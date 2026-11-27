import { describe, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { openApplicationDevice } from './device.js'
import { createLogGenesis } from './genesis.js'
import { createApplicationSession } from './runtime.js'
import { createLiveView } from './live-view.js'
import { queryFederatedSql } from './sql-extensions.js'

describe('Phase 3 P2P Merkle-paged SQL extensions', () => {
  it('supports zero-copy forkSql branching, row diffs, toProposal, time-travel queryAsOf, and audit log', async () => {
    const admin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createLogGenesis({
      creator: {
        publicKey: admin.identity.publicKey,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: true,
      },
      privateLog: false,
      topics: {
        $permissions: {
          module: 'chronolog/permissions',
          export: 'openMembers',
          initialState: { admins: [admin.identity.publicKey], members: [], openRead: true, openWrite: true, admission: null },
        },
        db: { module: 'chronolog/sql' },
      },
    })

    const s = await createApplicationSession({ device: admin, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      const mig = await s.command('db:migrate', {
        statements: [
          'CREATE TABLE items (id TEXT PRIMARY KEY, name TEXT NOT NULL, qty INTEGER NOT NULL, _last_op_id TEXT)',
          'CREATE TABLE logs (id TEXT PRIMARY KEY, msg TEXT NOT NULL)',
        ],
        stampTables: ['items'],
        auditTables: ['items'],
      }, { authorTimestampMs: 1000n })
      expect((await mig.materialized()).outcome).toBe('accepted')

      const op1 = await s.command('db:exec', {
        sql: 'INSERT INTO items (id, name, qty) VALUES (?, ?, ?)',
        params: ['sku-1', 'Coffee', 10],
      }, { authorTimestampMs: 2000n })
      expect((await op1.materialized()).outcome).toBe('accepted')

      const op2 = await s.command('db:exec', {
        sql: 'UPDATE items SET qty = ? WHERE id = ?',
        params: [25, 'sku-1'],
      }, { authorTimestampMs: 3000n })
      expect((await op2.materialized()).outcome).toBe('accepted')

      // 1. Time-travel queryAsOf by opId and by timestamp!
      const atOp1 = await s.queryAsOf('db', { sql: 'SELECT qty FROM items WHERE id = ?', params: ['sku-1'] }, { opId: op1.id })
      expect((atOp1.value as { rows: unknown[][] }).rows).toEqual([[10]])

      const atT2500 = await s.queryAsOf('db', { sql: 'SELECT qty FROM items WHERE id = ?', params: ['sku-1'] }, { atTimestampMs: 2500n })
      expect((atT2500.value as { rows: unknown[][] }).rows).toEqual([[10]])

      // Live state is still untouched at 25!
      const liveNow = (await s.query('db', { sql: 'SELECT qty FROM items WHERE id = ?', params: ['sku-1'] })).value as { rows: unknown[][] }
      expect(liveNow.rows).toEqual([[25]])

      // 2. Cryptographic audit log recorded actor(), op_id(), before/after JSON!
      const audit = (await s.query('db', { kind: 'audit', table: 'items' })).value as {
        audit: Array<{ action: string; actor: string; opId: string; before: Record<string, unknown> | null; after: Record<string, unknown> | null }>
      }
      expect(audit.audit.length).toBeGreaterThanOrEqual(2)
      const updateEntry = audit.audit.find(a => a.action === 'update' && a.opId === op2.id && a.before?.qty === 10 && a.after?.qty === 25)
      expect(updateEntry?.actor).toBe(admin.identity.publicKey)

      // 3. Zero-copy SQL branching (forkSql -> speculative mutations -> Merkle + row diff -> toProposal)
      const branch = await s.forkSql('db')
      try {
        branch.exec('UPDATE items SET qty = ? WHERE id = ?', [40, 'sku-1'])
        branch.exec('INSERT INTO items (id, name, qty) VALUES (?, ?, ?)', ['sku-2', 'Tea', 15])
        const proposal = branch.toProposal({ withRowGuards: true })

        expect(proposal.diff.merkle.totalChangedPages).toBeGreaterThan(0)
        expect(proposal.diff.tables).toHaveLength(1)
        expect(proposal.diff.tables[0]?.table).toBe('items')
        expect(proposal.diff.tables[0]?.inserted).toHaveLength(1)
        expect(proposal.diff.tables[0]?.updated).toHaveLength(1)
        expect(proposal.diff.tables[0]?.updated[0]?.before.qty).toBe(25)
        expect(proposal.diff.tables[0]?.updated[0]?.after.qty).toBe(40)
        expect(proposal.preconditions.length).toBe(1) // automatic based_on_row precondition!

        // Real DB is completely untouched by the branch!
        const stillLive = (await s.query('db', { sql: 'SELECT id, qty FROM items ORDER BY id' })).value as { rows: unknown[][] }
        expect(stillLive.rows).toEqual([['sku-1', 25]])

        // Apply the generated proposal cleanly!
        const applied = await s.command('db:exec', {
          preconditions: proposal.preconditions,
          statements: proposal.statements,
        }, { authorTimestampMs: 4000n })
        expect((await applied.materialized()).outcome).toBe('accepted')

        const afterApply = (await s.query('db', { sql: 'SELECT id, qty FROM items ORDER BY id' })).value as { rows: unknown[][] }
        expect(afterApply.rows).toEqual([['sku-1', 40], ['sku-2', 15]])
      } finally {
        branch.close()
      }

      // 4. Table-scoped reactive liveView skips re-derivation when unrelated table ('logs') is mutated!
      let deriveCount = 0
      const view = createLiveView(
        s,
        async (v) => {
          deriveCount++
          return v.query('db', { sql: 'SELECT count(*) FROM items' })
        },
        { watchTables: ['items'] },
      )
      try {
        await view.ready()
        await new Promise(r => setTimeout(r, 30))
        const baseline = deriveCount

        // Write to unrelated table 'logs' -> should NOT re-derive items view!
        const logOp = await s.command('db:exec', {
          sql: 'INSERT INTO logs (id, msg) VALUES (?, ?)',
          params: ['l1', 'hello'],
        }, { authorTimestampMs: 5000n })
        expect((await logOp.materialized()).outcome).toBe('accepted')
        await new Promise(r => setTimeout(r, 40))
        expect(deriveCount).toBe(baseline)

        // Write to watched table 'items' -> DOES re-derive!
        const itemOp = await s.command('db:exec', {
          sql: 'INSERT INTO items (id, name, qty) VALUES (?, ?, ?)',
          params: ['sku-3', 'Matcha', 5],
        }, { authorTimestampMs: 6000n })
        expect((await itemOp.materialized()).outcome).toBe('accepted')
        await new Promise(r => setTimeout(r, 60))
        expect(deriveCount).toBe(baseline + 1)
      } finally {
        view.close()
      }
    } finally {
      await s.close()
    }
  })

  it('executes zero-trust federated cross-page SQL JOINs across two separately encrypted logs', async () => {
    const makePrivateSqlLog = async () => {
      const dev = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
      const created = await createLogGenesis({
        creator: {
          publicKey: dev.identity.publicKey,
          wrapKey: dev.wrapKey.publicKey,
          reader: true,
          writer: true,
          administrator: true,
          publisher: true,
          finalizer: true,
        },
        privateLog: true,
        topics: {
          db: { module: 'chronolog/sql' },
        },
      })
      const session = await createApplicationSession({
        device: dev,
        genesis: created.genesisBytes,
        casNodes: created.casNodes,
        epochKeys: new Map([[0, created.epoch0Key!]]),
      })
      return session
    }

    const contactsSession = await makePrivateSqlLog()
    const projectsSession = await makePrivateSqlLog()
    try {
      await (await contactsSession.command('db:migrate', {
        statements: ['CREATE TABLE people (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL)'],
      })).materialized()
      await (await contactsSession.command('db:exec', {
        statements: [
          { sql: 'INSERT INTO people VALUES (?, ?, ?)', params: ['p1', 'Ada', 'Architect'] },
          { sql: 'INSERT INTO people VALUES (?, ?, ?)', params: ['p2', 'Linus', 'Systems'] },
        ],
      })).materialized()

      await (await projectsSession.command('db:migrate', {
        statements: ['CREATE TABLE tasks (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, title TEXT NOT NULL)'],
      })).materialized()
      await (await projectsSession.command('db:exec', {
        statements: [
          { sql: 'INSERT INTO tasks VALUES (?, ?, ?)', params: ['t1', 'p1', 'Design Merkle SQL'] },
          { sql: 'INSERT INTO tasks VALUES (?, ?, ?)', params: ['t2', 'p2', 'Ship Kernel'] },
        ],
      })).materialized()

      // Join across both separately encrypted databases locally!
      const joined = await queryFederatedSql(
        {
          contacts: { session: contactsSession, topic: 'db' },
          projects: { session: projectsSession, topic: 'db' },
        },
        'SELECT p.name, p.role, t.title FROM contacts__people p JOIN projects__tasks t ON p.id = t.owner_id ORDER BY t.id',
        [],
        { format: 'objects' },
      )
      expect(joined.mountedTables).toEqual(['contacts__people', 'projects__tasks'])
      expect(joined.rows).toEqual([
        { name: 'Ada', role: 'Architect', title: 'Design Merkle SQL' },
        { name: 'Linus', role: 'Systems', title: 'Ship Kernel' },
      ])
    } finally {
      await contactsSession.close()
      await projectsSession.close()
    }
  })
})

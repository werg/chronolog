import { describe, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { openApplicationDevice } from './device.js'
import { createLogGenesis } from './genesis.js'
import { createApplicationSession } from './runtime.js'

describe('Universal operation assumptions & ergonomic SQL row guards', () => {
  it('heals out-of-order afterOps dependencies, cascades rejections, and runs requiresRejected fallbacks', async () => {
    const alice = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const bob = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createLogGenesis({
      creator: {
        publicKey: alice.identity.publicKey,
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
          initialState: {
            admins: [alice.identity.publicKey],
            members: [],
            openRead: true,
            openWrite: true,
            admission: null,
          },
        },
        db: { module: 'chronolog/sql' },
      },
    })

    const sAlice = await createApplicationSession({ device: alice, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sBob = await createApplicationSession({ device: bob, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      const mig = await sAlice.command('db:migrate', {
        statements: [
          'CREATE TABLE bookings (slot TEXT PRIMARY KEY, owner TEXT NOT NULL)',
          'CREATE TABLE notes (id TEXT PRIMARY KEY, body TEXT NOT NULL)',
        ],
      }, { authorTimestampMs: 1000n })
      expect((await mig.materialized()).outcome).toBe('accepted')
      await sBob.mergeFacts(await sAlice.exportFacts())

      // Bob claims 2pm at t=2000, then adds a dependent confirmation note at t=2001 (auto-clamped)
      const bobClaim = await sBob.command('db:exec', {
        sql: 'INSERT INTO bookings (slot, owner) VALUES (?, ?)',
        params: ['14:00', 'bob'],
      }, { authorTimestampMs: 2000n })
      expect((await bobClaim.materialized()).outcome).toBe('accepted')

      // Even with a clock-skewed local wall clock, omitting authorTimestampMs clamps past bobClaim (2000n -> >= 2001n)
      const bobNote = await sBob.command('db:exec', {
        sql: 'INSERT INTO notes (id, body) VALUES (?, ?)',
        params: ['n1', 'confirmed 14:00'],
      }, { afterOps: [bobClaim.id] })
      expect((await bobNote.materialized()).outcome).toBe('accepted')
      expect(BigInt(bobNote.inspect().authorTimestampMs ?? '0') >= 2001n).toBe(true)

      // Bob also submits a deterministic fallback for 14:30 that ONLY runs if bobClaim is rejected!
      const bobFallback = await sBob.command('db:exec', {
        sql: 'INSERT INTO bookings (slot, owner) VALUES (?, ?)',
        params: ['14:30', 'bob'],
      }, { requiresRejected: [bobClaim.id], authorTimestampMs: 2500n })
      expect((await bobFallback.materialized()).outcome).toBe('rejected')
      expect((await bobFallback.materialized()).rejectionCode).toBe('assumption:expected_rejected')

      // Out-of-order test on a fresh peer (observer receives bobNote BEFORE bobClaim):
      const observerDev = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
      const sObs = await createApplicationSession({ device: observerDev, genesis: created.genesisBytes, casNodes: created.casNodes })
      try {
        const bobFacts = await sBob.exportFacts()
        // Ingest migration + bobNote only (skip bobClaim & bobFallback)
        await sObs.mergeFacts({
          ...bobFacts,
          publicOps: bobFacts.publicOps.filter((_, idx) => idx === 0 || idx === 2),
        })
        expect(sObs.opOutcome(bobNote.id)).toBe('rejected')
        // Now deliver bobClaim -> bobNote heals automatically to accepted!
        await sObs.mergeFacts(bobFacts)
        expect(sObs.opOutcome(bobClaim.id)).toBe('accepted')
        expect(sObs.opOutcome(bobNote.id)).toBe('accepted')
      } finally {
        await sObs.close()
      }

      // Now Alice claims 14:00 at an EARLIER timestamp (t=1500) offline!
      const aliceClaim = await sAlice.command('db:exec', {
        sql: 'INSERT INTO bookings (slot, owner) VALUES (?, ?)',
        params: ['14:00', 'alice'],
      }, { authorTimestampMs: 1500n })
      expect((await aliceClaim.materialized()).outcome).toBe('accepted')

      // Sync both peers -> Alice wins 14:00, Bob's 14:00 fails UNIQUE,
      // Bob's dependent note CASCADES to rejected, and Bob's fallback 14:30 AUTOMATICALLY ACCEPTS!
      await sBob.mergeFacts(await sAlice.exportFacts())
      await sAlice.mergeFacts(await sBob.exportFacts())

      expect(sBob.opOutcome(aliceClaim.id)).toBe('accepted')
      expect(sBob.opOutcome(bobClaim.id)).toBe('rejected')
      expect(sBob.opOutcome(bobNote.id)).toBe('rejected')
      expect(sBob.opOutcome(bobFallback.id)).toBe('accepted')

      const rows = (await sAlice.query('db', { sql: 'SELECT slot, owner FROM bookings ORDER BY slot' })).value as { rows: unknown[][] }
      expect(rows.rows).toEqual([['14:00', 'alice'], ['14:30', 'bob']])
      const notes = (await sAlice.query('db', { sql: 'SELECT id FROM notes' })).value as { rows: unknown[][] }
      expect(notes.rows).toEqual([])
    } finally {
      await sAlice.close()
      await sBob.close()
    }
  })

  it('supports topic_revision, query_match, based_on_row, row_matches, and record_conflict inbox', async () => {
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
          initialState: {
            admins: [admin.identity.publicKey],
            members: [],
            openRead: true,
            openWrite: true,
            admission: null,
          },
        },
        db: { module: 'chronolog/sql' },
      },
    })

    const s = await createApplicationSession({ device: admin, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      const mig = await s.command('db:migrate', {
        statements: [
          'CREATE TABLE invoices (id TEXT PRIMARY KEY, total INTEGER NOT NULL, status TEXT NOT NULL, _last_op_id TEXT, _updated_at INTEGER)',
        ],
        stampTables: ['invoices'],
        stampUpdatedAt: true,
      })
      expect((await mig.materialized()).outcome).toBe('accepted')

      const ins = await s.command('db:exec', {
        sql: 'INSERT INTO invoices (id, total, status) VALUES (?, ?, ?)',
        params: ['inv-1', 5000, 'draft'],
      })
      expect((await ins.materialized()).outcome).toBe('accepted')

      // Trigger stamped _last_op_id automatically!
      const rowRes = (await s.query('db', { sql: 'SELECT id, total, _last_op_id FROM invoices WHERE id = ?', params: ['inv-1'], format: 'objects' })).value as {
        rows: Array<{ id: string; total: number; _last_op_id: string }>
      }
      expect(rowRes.rows[0]?._last_op_id).toBe(ins.id)
      const stampedOpId = rowRes.rows[0]!._last_op_id

      // Succeeds when based_on_row & row_matches hold:
      const upd1 = await s.command('db:exec', {
        preconditions: [
          { kind: 'based_on_row', table: 'invoices', where: { id: 'inv-1' }, lastOpId: stampedOpId },
          { kind: 'row_matches', table: 'invoices', where: { id: 'inv-1' }, expect: { status: 'draft', total: 5000 } },
        ],
        sql: 'UPDATE invoices SET total = ? WHERE id = ?',
        params: [7500, 'inv-1'],
      })
      expect((await upd1.materialized()).outcome).toBe('accepted')

      // Stale topic_revision with onAssumptionFailed: 'record_conflict' records into _chronolog_conflicts
      // while still marking opOutcome as 'rejected' so downstream afterOps do not treat it as applied!
      const staleApprove = await s.command('db:exec', {
        sql: 'UPDATE invoices SET status = ? WHERE id = ?',
        params: ['approved', 'inv-1'],
      }, {
        assumptions: {
          checks: [
            { kind: 'topic_revision', topic: 'db', lastOpId: ins.id },
          ],
          onFailed: 'record_conflict',
        },
      })
      const mat = await staleApprove.materialized()
      expect(mat.outcome).toBe('rejected')
      expect(mat.rejectionCode).toBe('assumption:topic_modified')
      expect(s.opOutcome(staleApprove.id)).toBe('rejected')

      // Verify invoice stayed 'draft' AND conflict was recorded in _chronolog_conflicts!
      const invAfter = (await s.query('db', { sql: 'SELECT total, status FROM invoices WHERE id = ?', params: ['inv-1'] })).value as { rows: unknown[][] }
      expect(invAfter.rows).toEqual([[7500, 'draft']])

      const conflicts = (await s.query('db', { kind: 'conflicts' })).value as { conflicts: Array<{ opId: string; code: string; resolved: boolean }> }
      expect(conflicts.conflicts).toHaveLength(1)
      expect(conflicts.conflicts[0]?.opId).toBe(staleApprove.id)
      expect(conflicts.conflicts[0]?.code).toBe('assumption:topic_modified')
      expect(conflicts.conflicts[0]?.resolved).toBe(false)

      // Resolve conflict cleanly
      const res = await s.command('db:resolveConflict', { opId: staleApprove.id, resolution: 'reapplied-at-7500' })
      expect((await res.materialized()).outcome).toBe('accepted')
      const remaining = (await s.query('db', { kind: 'conflicts', unresolvedOnly: true })).value as { conflicts: unknown[] }
      expect(remaining.conflicts).toHaveLength(0)

      // Test query_match universal assumption
      const qOk = await s.command('db:exec', {
        sql: 'UPDATE invoices SET status = ? WHERE id = ?',
        params: ['paid', 'inv-1'],
      }, {
        assumptions: {
          checks: [
            {
              kind: 'query_match',
              topic: 'db',
              query: { sql: 'SELECT total FROM invoices WHERE id = ?', params: ['inv-1'] },
              expect: { columns: ['total'], rows: [[7500]] },
            },
          ],
        },
      })
      expect((await qOk.materialized()).outcome).toBe('accepted')
    } finally {
      await s.close()
    }
  })
})

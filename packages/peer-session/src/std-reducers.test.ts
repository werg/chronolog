import { describe, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { openApplicationDevice } from './device.js'
import { createLogGenesis } from './genesis.js'
import { createApplicationSession } from './runtime.js'

describe('Phase 2 standard reducers: crdt, text, ledger, workflow, fs', () => {
  it('converges lwwMap, orSet, pnCounter, orderedList, and collaborativeText under shuffled arrival', async () => {
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
          initialState: { admins: [alice.identity.publicKey], members: [], openRead: true, openWrite: true, admission: null },
        },
        prefs: { module: 'chronolog/crdt', export: 'lwwMap' },
        tags: { module: 'chronolog/crdt', export: 'orSet' },
        likes: { module: 'chronolog/crdt', export: 'pnCounter' },
        kanban: { module: 'chronolog/crdt', export: 'orderedList' },
        doc: { module: 'chronolog/text', export: 'collaborativeText' },
      },
    })

    const sA = await createApplicationSession({ device: alice, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sB = await createApplicationSession({ device: bob, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      // Concurrent writes on both peers offline
      await sA.command('prefs:set', { key: 'theme', value: 'forest' }, { authorTimestampMs: 1000n })
      await sB.command('prefs:set', { key: 'theme', value: 'midnight' }, { authorTimestampMs: 2000n })
      await sA.command('prefs:merge', { values: { lang: 'en', density: 'compact' } }, { authorTimestampMs: 1500n })

      await sA.command('tags:add', { value: 'p2p' }, { authorTimestampMs: 1000n })
      await sB.command('tags:add', { value: 'sql' }, { authorTimestampMs: 1100n })
      await sA.command('tags:add', { value: 'temp' }, { authorTimestampMs: 1200n })
      await sA.command('tags:remove', { value: 'temp' }, { authorTimestampMs: 1300n })

      await sA.command('likes:increment', { amount: 5 }, { authorTimestampMs: 1000n })
      await sB.command('likes:increment', { amount: 3 }, { authorTimestampMs: 1050n })
      await sB.command('likes:decrement', { amount: 2 }, { authorTimestampMs: 1100n })

      const k1 = await sA.command('kanban:insert', { id: 'card-1', afterId: null, value: 'Design' }, { authorTimestampMs: 1000n })
      expect((await k1.materialized()).outcome).toBe('accepted')
      await sA.command('kanban:insert', { id: 'card-2', afterId: 'card-1', value: 'Build' }, { authorTimestampMs: 1100n })
      await sB.command('kanban:insert', { id: 'card-3', afterId: null, value: 'Launch' }, { authorTimestampMs: 1200n })

      // Collaborative text: Alice inserts "Hello ", Bob concurrently inserts "World"
      const t1 = await sA.command('doc:insert', { afterId: null, text: 'Hello ' }, { authorTimestampMs: 1000n })
      expect((await t1.materialized()).outcome).toBe('accepted')
      await sB.mergeFacts(await sA.exportFacts())
      const snapA = (await sA.query('doc', { kind: 'text' })).value as { text: string; lastNodeId: string }
      expect(snapA.text).toBe('Hello ')
      await sA.command('doc:insert', { afterId: snapA.lastNodeId, text: 'Alice' }, { authorTimestampMs: 2000n })
      await sB.command('doc:insert', { afterId: snapA.lastNodeId, text: 'Bob' }, { authorTimestampMs: 2100n })

      // Exchange facts in both directions and verify byte-identical stateRoot convergence!
      const factsA = await sA.exportFacts()
      const factsB = await sB.exportFacts()
      await sA.mergeFacts(factsB)
      await sB.mergeFacts(factsA)

      expect(sA.revision().stateRoot).toBe(sB.revision().stateRoot)
      expect((await sA.query('prefs')).value).toEqual({ density: 'compact', lang: 'en', theme: 'midnight' })
      expect(((await sA.query('tags')).value as { values: string[] }).values).toEqual(['p2p', 'sql'])
      expect(((await sA.query('likes')).value as { value: number }).value).toBe(6)
      expect(((await sA.query('kanban')).value as { items: Array<{ id: string }> }).items.map(i => i.id)).toEqual(['card-3', 'card-1', 'card-2'])
      // Bob's newer concurrent insert right after "Hello " deterministically orders before Alice's
      expect(((await sA.query('doc')).value as { text: string }).text).toBe('Hello BobAlice')
      expect(((await sB.query('doc')).value as { text: string }).text).toBe('Hello BobAlice')
    } finally {
      await sA.close()
      await sB.close()
    }
  })

  it('enforces double-entry invariants, expiring holds, and offline Escrow CRDT allowances in chronolog/ledger', async () => {
    const admin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const agent = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
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
        ledger: { module: 'chronolog/ledger', export: 'doubleEntryLedger' },
      },
    })

    const sAdmin = await createApplicationSession({ device: admin, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sAgent = await createApplicationSession({ device: agent, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      await sAdmin.command('ledger:createAccount', { id: 'equity', allowNegative: true }, { authorTimestampMs: 1000n })
      await sAdmin.command('ledger:createAccount', { id: 'treasury' }, { authorTimestampMs: 1001n })
      await sAdmin.command('ledger:createAccount', { id: 'vendor' }, { authorTimestampMs: 1002n })

      // Fund treasury with $100.00 (10000 cents)
      const fund = await sAdmin.command('ledger:post', {
        postings: [{ account: 'equity', delta: -10000 }, { account: 'treasury', delta: 10000 }],
        memo: 'initial funding',
      }, { authorTimestampMs: 1010n })
      expect((await fund.materialized()).outcome).toBe('accepted')

      // Unbalanced posting rejected
      const bad = await sAdmin.command('ledger:post', {
        postings: [{ account: 'treasury', delta: -100 }, { account: 'vendor', delta: 50 }],
      }, { authorTimestampMs: 1011n })
      expect((await bad.materialized()).rejectionCode).toBe('ledger:unbalanced')

      // Hold $60 expiring at t=2000
      const hold = await sAdmin.command('ledger:hold', {
        holdId: 'h1',
        from: 'treasury',
        to: 'vendor',
        amount: 6000,
        expiresAtMs: 2000,
      }, { authorTimestampMs: 1020n })
      expect((await hold.materialized()).outcome).toBe('accepted')

      // Trying to spend $50 while $60 is held fails (only $40 available)
      const failOver = await sAdmin.command('ledger:post', {
        postings: [{ account: 'treasury', delta: -5000 }, { account: 'vendor', delta: 5000 }],
      }, { authorTimestampMs: 1500n })
      expect((await failOver.materialized()).rejectionCode).toBe('ledger:insufficient_funds')

      // Grant agent a $30 offline allowance (t=1600)
      const grant = await sAdmin.command('ledger:grantAllowance', {
        allowanceId: 'agent-daily',
        fromAccount: 'treasury',
        grantee: agent.identity.publicKey,
        amount: 3000,
        expiresAtMs: 5000,
      }, { authorTimestampMs: 1600n })
      expect((await grant.materialized()).outcome).toBe('accepted')

      // Sync to agent -> agent spends offline within allowance ($12 + $15 = $27 ok, + $5 = rejected!)
      await sAgent.mergeFacts(await sAdmin.exportFacts())
      const sp1 = await sAgent.command('ledger:spendFromAllowance', {
        allowanceId: 'agent-daily',
        toAccount: 'vendor',
        amount: 1200,
        memo: 'api call 1',
      }, { authorTimestampMs: 2100n })
      const sp2 = await sAgent.command('ledger:spendFromAllowance', {
        allowanceId: 'agent-daily',
        toAccount: 'vendor',
        amount: 1500,
        memo: 'api call 2',
      }, { authorTimestampMs: 2200n })
      const sp3 = await sAgent.command('ledger:spendFromAllowance', {
        allowanceId: 'agent-daily',
        toAccount: 'vendor',
        amount: 500,
        memo: 'over budget',
      }, { authorTimestampMs: 2300n })

      expect((await sp1.materialized()).outcome).toBe('accepted')
      expect((await sp2.materialized()).outcome).toBe('accepted')
      expect((await sp3.materialized()).rejectionCode).toBe('ledger:allowance_exceeded')

      // Hold h1 expired at t=2000, so captureHold at t=2500 fails with ledger:hold_expired
      const lateCapture = await sAdmin.command('ledger:captureHold', { holdId: 'h1' }, { authorTimestampMs: 2500n })
      expect((await lateCapture.materialized()).rejectionCode).toBe('ledger:hold_expired')

      await sAdmin.mergeFacts(await sAgent.exportFacts())
      const balances = (await sAdmin.query('ledger', { kind: 'balances', atMs: 2600 })).value as {
        balances: Record<string, { balance: number; available: number }>
      }
      expect(balances.balances.treasury?.balance).toBe(7300) // 10000 - 2700
      expect(balances.balances.treasury?.available).toBe(7000) // 7300 - 300 remaining allowance
      expect(balances.balances.vendor?.balance).toBe(2700)
    } finally {
      await sAdmin.close()
      await sAgent.close()
    }
  })

  it('supports chronolog/workflow separation of duties + M-of-N approvals and chronolog/fs auto-conflict forks', async () => {
    const admin1 = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const admin2 = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const agent = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createLogGenesis({
      creator: {
        publicKey: admin1.identity.publicKey,
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
          initialState: { admins: [admin1.identity.publicKey, admin2.identity.publicKey], members: [], openRead: true, openWrite: true, admission: null },
        },
        proposals: {
          module: 'chronolog/workflow',
          export: 'stateMachine',
          config: {
            definition: {
              initialState: 'proposed',
              states: ['proposed', 'approved', 'expired'],
              transitions: [
                {
                  name: 'approve',
                  from: 'proposed',
                  to: 'approved',
                  roles: ['administrator'],
                  distinctFromCreator: true,
                  requiredApprovals: 2,
                  slaMs: 5000,
                  expiredTo: 'expired',
                },
              ],
            },
          },
        },
        files: { module: 'chronolog/fs', export: 'virtualFs' },
      },
    })

    const s1 = await createApplicationSession({ device: admin1, genesis: created.genesisBytes, casNodes: created.casNodes })
    const s2 = await createApplicationSession({ device: admin2, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sAgent = await createApplicationSession({ device: agent, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      // Agent creates a proposal
      const prop = await sAgent.command('proposals:create', { id: 'pr-1', title: 'Reconcile Q4', payload: { edits: 6 } }, { authorTimestampMs: 1000n })
      expect((await prop.materialized()).outcome).toBe('accepted')

      // Admin1 creates a self-proposal and cannot approve it (separation of duties)
      await s1.command('proposals:create', { id: 'pr-self', title: 'Self edit' }, { authorTimestampMs: 1000n })
      const selfApprove = await s1.command('proposals:transition', { id: 'pr-self', transition: 'approve' }, { authorTimestampMs: 1100n })
      expect((await selfApprove.materialized()).rejectionCode).toBe('workflow:separation_of_duties')

      // Admin1 + Admin2 both approve pr-1 (2-of-2 required)
      await s1.mergeFacts(await sAgent.exportFacts())
      const ap1 = await s1.command('proposals:transition', { id: 'pr-1', transition: 'approve' }, { authorTimestampMs: 1200n })
      expect((await ap1.materialized()).outcome).toBe('accepted')
      expect(((await s1.query('proposals', { kind: 'item', id: 'pr-1' })).value as { state: string }).state).toBe('proposed')

      await s2.mergeFacts(await s1.exportFacts())
      const ap2 = await s2.command('proposals:transition', { id: 'pr-1', transition: 'approve' }, { authorTimestampMs: 1300n })
      expect((await ap2.materialized()).outcome).toBe('accepted')
      expect(((await s2.query('proposals', { kind: 'item', id: 'pr-1' })).value as { state: string }).state).toBe('approved')

      // SLA expiry on pr-self after 5000ms
      const exp = await s1.command('proposals:expire', { id: 'pr-self' }, { authorTimestampMs: 7000n })
      expect((await exp.materialized()).outcome).toBe('accepted')
      expect(((await s1.query('proposals', { kind: 'item', id: 'pr-self' })).value as { state: string }).state).toBe('expired')

      // Virtual FS: write v1, then two concurrent edits referencing v1 -> second auto-forks into conflict sibling!
      const w1 = await s1.command('files:writeFile', { path: '/docs/plan.md', ref: { id: 'hash-v1' }, bytes: 100, mediaType: 'text/markdown' }, { authorTimestampMs: 1000n })
      expect((await w1.materialized()).outcome).toBe('accepted')
      await s2.mergeFacts(await s1.exportFacts())

      const w2a = await s1.command('files:writeFile', { path: '/docs/plan.md', ref: { id: 'hash-v2a' }, bytes: 120, expectedOpId: w1.id }, { authorTimestampMs: 2000n })
      const w2b = await s2.command('files:writeFile', { path: '/docs/plan.md', ref: { id: 'hash-v2b' }, bytes: 130, expectedOpId: w1.id }, { authorTimestampMs: 2100n })
      expect(await w2a.materialized()).toMatchObject({ outcome: 'accepted', rejectionCode: null })
      expect(await w2b.materialized()).toMatchObject({ outcome: 'accepted', rejectionCode: null })

      await s1.mergeFacts(await s2.exportFacts())
      const conflicts = (await s1.query('files', { kind: 'conflicts' })).value as { conflicts: Array<{ path: string; conflictOf: string }> }
      expect(conflicts.conflicts).toHaveLength(1)
      expect(conflicts.conflicts[0]?.conflictOf).toBe('/docs/plan.md')

      // Resolve conflict by replacing original
      const resolve = await s1.command('files:resolveConflict', {
        conflictPath: conflicts.conflicts[0]!.path,
        strategy: 'replace_original',
      }, { authorTimestampMs: 3000n })
      expect((await resolve.materialized()).outcome).toBe('accepted')
      const finalStat = (await s1.query('files', { kind: 'stat', path: '/docs/plan.md' })).value as { ref: { id: string } }
      expect(finalStat.ref.id).toBe('hash-v2b')
    } finally {
      await s1.close()
      await s2.close()
      await sAgent.close()
    }
  })
})

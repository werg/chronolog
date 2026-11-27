import { describe, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { openApplicationDevice } from './device.js'
import { createLogGenesis } from './genesis.js'
import { createApplicationSession } from './runtime.js'
import { createApplicationOwner } from './session-owner.js'
import { WorkerApplicationSession } from './worker-application.js'

describe('Worker RPC bridge for SQL branching, time-travel, social recovery, compartments & finality', () => {
  it('forwards forkSql, queryAsOf, afterOps, finalityStatus, compartments, and social recovery over MessageChannel', async () => {
    const ownerDev = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const g1Dev = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const freshDev = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    const created = await createLogGenesis({
      creator: {
        publicKey: ownerDev.identity.publicKey,
        wrapKey: ownerDev.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: true,
      },
      privateLog: true,
      topics: {
        db: { module: 'chronolog/sql' },
        vault: { module: 'chronolog/crdt', export: 'lwwMap' },
      },
    })

    const rawOwnerSession = await createApplicationSession({
      device: ownerDev,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys: new Map([[0, created.epoch0Key!]]),
    })
    const ownerHost = createApplicationOwner(rawOwnerSession)
    const ch = new MessageChannel()
    ownerHost.attach(ch.port1)
    ch.port1.start()
    ch.port2.start()

    const client = new WorkerApplicationSession(ch.port2)
    await client.initialize({ applicationId: rawOwnerSession.applicationId })

    try {
      // 1. Migrate + stamp + exec with causal afterOps over Worker RPC
      const mig = await client.command('db:migrate', {
        statements: ['CREATE TABLE items (id TEXT PRIMARY KEY, qty INTEGER NOT NULL, _last_op_id TEXT)'],
        stampTables: ['items'],
      }, { authorTimestampMs: 1000n })
      expect((await mig.materialized()).outcome).toBe('accepted')

      const op1 = await client.command('db:exec', {
        sql: 'INSERT INTO items (id, qty) VALUES (?, ?)',
        params: ['a', 5],
      }, { authorTimestampMs: 2000n })
      expect((await op1.materialized()).outcome).toBe('accepted')

      const op2 = await client.command('db:exec', {
        sql: 'UPDATE items SET qty = ? WHERE id = ?',
        params: [12, 'a'],
      }, { afterOps: [op1.id], authorTimestampMs: 3000n })
      expect((await op2.materialized()).outcome).toBe('accepted')

      // 2. Time-travel queryAsOf, opOutcome, topicLastOpId, finalityStatus, equivocationProofs over RPC
      const hist = await client.queryAsOf('db', { sql: 'SELECT qty FROM items WHERE id = ?', params: ['a'] }, { opId: op1.id })
      expect((hist.value as { rows: unknown[][] }).rows).toEqual([[5]])
      expect(await client.opOutcome(op2.id)).toBe('accepted')
      expect(await client.topicLastOpId('db')).toBe(op2.id)
      expect(await client.finalityStatus(op2.id)).toBe('local')
      expect(await client.equivocationProofs()).toEqual([])

      // 3. Zero-copy forkSql branch -> exec -> diff -> toProposal -> close over RPC
      const branch = await client.forkSql('db')
      try {
        await branch.exec('UPDATE items SET qty = ? WHERE id = ?', [20, 'a'])
        const proposal = await branch.toProposal({ withRowGuards: true })
        expect(proposal.diff.tables[0]?.updated[0]?.before.qty).toBe(12)
        expect(proposal.diff.tables[0]?.updated[0]?.after.qty).toBe(20)
        expect(proposal.preconditions).toHaveLength(1)
      } finally {
        await branch.close()
      }

      // 4. Compartment creation + Social Recovery setup over RPC
      const comp = await client.createCompartment('admins', {
        topics: ['vault'],
        members: [{ publicKey: ownerDev.identity.publicKey, wrapKey: ownerDev.wrapKey.publicKey }],
      })
      expect((await comp.operation.materialized()).outcome).toBe('accepted')

      const setupOp = await client.setupSocialRecovery({
        threshold: 1,
        guardians: [{ publicKey: g1Dev.identity.publicKey, wrapKey: g1Dev.wrapKey.publicKey, label: 'Backup' }],
      })
      expect((await setupOp.materialized()).outcome).toBe('accepted')

      // Guardian approves and fresh device completes recovery via Worker RPC too!
      const rawG1 = await createApplicationSession({ device: g1Dev, genesis: created.genesisBytes, casNodes: created.casNodes })
      const rawFresh = await createApplicationSession({ device: freshDev, genesis: created.genesisBytes, casNodes: created.casNodes })
      const g1Host = createApplicationOwner(rawG1)
      const freshHost = createApplicationOwner(rawFresh)
      const chG1 = new MessageChannel()
      const chFresh = new MessageChannel()
      g1Host.attach(chG1.port1); chG1.port1.start(); chG1.port2.start()
      freshHost.attach(chFresh.port1); chFresh.port1.start(); chFresh.port2.start()
      const g1Client = new WorkerApplicationSession(chG1.port2)
      const freshClient = new WorkerApplicationSession(chFresh.port2)
      await g1Client.initialize({ applicationId: rawOwnerSession.applicationId })
      await freshClient.initialize({ applicationId: rawOwnerSession.applicationId })

      try {
        const f0 = await client.exportFacts()
        await g1Client.mergeFacts(f0)
        await freshClient.mergeFacts(f0)

        const req = await freshClient.requestSocialRecovery({ label: 'Recovered Browser' })
        expect((await req.operation.materialized()).outcome).toBe('accepted')

        await g1Client.mergeFacts(await freshClient.exportFacts())
        const app = await g1Client.approveSocialRecovery(req.requestId)
        expect((await app.materialized()).outcome).toBe('accepted')

        await freshClient.mergeFacts(await g1Client.exportFacts())
        const restored = await freshClient.completeSocialRecovery()
        expect(restored.restoredEpochs).toBe(1)
        const rows = (await freshClient.query('db', { sql: 'SELECT qty FROM items WHERE id = ?', params: ['a'] })).value as { rows: unknown[][] }
        expect(rows.rows).toEqual([[12]])
      } finally {
        await g1Client.close()
        await freshClient.close()
        await g1Host.close()
        await freshHost.close()
      }
    } finally {
      await client.close()
      await ownerHost.close()
    }
  })
})

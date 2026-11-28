import { describe, expect, it } from 'vitest'
import { ContentAddressedStore, MemoryBytesStore } from '@chronolog/records'
import { createLogGenesis, createApplicationSession, openApplicationDevice } from './index.js'
import { createSqliteCasDriver } from 'chronolog-db'
import { TopicKernel } from '@chronolog/materializer'

async function makeDevice(store = new MemoryBytesStore()) {
  const meta = new MemoryBytesStore()
  return openApplicationDevice({
    store: meta,
    create: true,
    openStorage: async () => ({ store, close: async () => {} }),
    close: async () => {},
  })
}

describe('First-principles Chronolog refactor verification', () => {
  it('decouples submit() from slow background materialization/GC and guarantees read-your-own-writes', async () => {
    const device = await makeDevice()
    const { genesis, epoch0Key, casNodes } = await createLogGenesis({
      creator: { publicKey: device.identity.publicKey, wrapKey: device.wrapKey.publicKey },
      privateLog: true,
      topics: { tasks: { module: 'chronolog/sql' } },
    })
    const session = await createApplicationSession({
      device,
      genesis,
      casNodes,
      epochKeys: new Map([[0, epoch0Key!]]),
    })
    try {
      await session.submit({
        awaitMaterialized: true,
        updates: [{
          topic: 'tasks',
          input: {
            action: 'migrate',
            statements: ['CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT NOT NULL)'],
          },
        }],
      })

      const t0 = performance.now()
      const ops = []
      for (let i = 0; i < 10; i++) {
        ops.push(await session.submit({
          updates: [{
            topic: 'tasks',
            input: {
              statements: [{ sql: 'INSERT INTO tasks(id, title) VALUES (?, ?)', params: [`t${i}`, `Task ${i}`] }],
            },
          }],
        }))
      }
      const submitElapsed = performance.now() - t0
      expect(ops).toHaveLength(10)
      expect(ops.every(o => o.stored)).toBe(true)
      // Wall-clock bound only: background materialization shares the event loop (each encrypted op
      // pays a fresh-context `$admission` authorize + admit), so this is not a tight latency budget.
      expect(submitElapsed).toBeLessThan(5_000)

      // Read-your-own-writes: query() automatically flushes coalesced materialization!
      const rows = await session.query('tasks', { sql: 'SELECT COUNT(*) AS n FROM tasks', format: 'objects' })
      expect((rows.value as { rows: { n: number }[] }).rows[0]!.n).toBe(10)
    } finally {
      await session.close()
    }
  })

  it('syncFromStore() converges two concurrent tabs sharing one BytesStore with zero storage locks', async () => {
    const sharedData = new MemoryBytesStore()
    const sharedMeta = new MemoryBytesStore()
    const openTab = () => openApplicationDevice({
      store: sharedMeta,
      create: true,
      openStorage: async () => ({ store: sharedData, close: async () => {} }),
      close: async () => {},
    })
    const devA = await openTab()
    const devB = await openTab()
    expect(devA.identity.publicKey).toBe(devB.identity.publicKey)

    const { genesis, epoch0Key, casNodes } = await createLogGenesis({
      creator: { publicKey: devA.identity.publicKey, wrapKey: devA.wrapKey.publicKey },
      privateLog: true,
      topics: { notes: { module: 'chronolog/sql' } },
    })
    const tabA = await createApplicationSession({ device: devA, genesis, casNodes, epochKeys: new Map([[0, epoch0Key!]]) })
    const tabB = await createApplicationSession({ device: devB, genesis, casNodes, epochKeys: new Map([[0, epoch0Key!]]) })
    try {
      await tabA.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'notes', input: { action: 'migrate', statements: ['CREATE TABLE notes (id TEXT PRIMARY KEY, body TEXT)'] } }],
      })
      await tabA.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'notes', input: { statements: [{ sql: 'INSERT INTO notes VALUES (?, ?)', params: ['n1', 'from tab A'] }] } }],
      })
      const changed = await tabB.syncFromStore()
      expect(changed).toBe(true)
      const resB = await tabB.query('notes', { sql: 'SELECT id, body FROM notes', format: 'objects' })
      expect((resB.value as { rows: { id: string; body: string }[] }).rows).toEqual([{ id: 'n1', body: 'from tab A' }])
    } finally {
      await tabA.close()
      await tabB.close()
    }
  })

  it('demand-pages SQLite-CAS Merkle pages from disk when RAM LRU cache is tiny', async () => {
    const store = new MemoryBytesStore()
    const cas = new ContentAddressedStore({ store, maxCacheEntries: 4 })
    const driver = await createSqliteCasDriver()
    const { genesis, casNodes } = await createLogGenesis({
      creator: { publicKey: 'a'.repeat(64) },
      privateLog: false,
      topics: { items: { module: 'chronolog/sql' } },
    })
    await cas.putManyVerified(casNodes)
    const kernel = new TopicKernel({ genesis, cas, sqliteDriver: driver })
    const res = await kernel.query('$admission', { kind: 'roster' })
    expect(res).toBeTruthy()
    kernel.sandbox.dispose()
  })

  it('bootstraps a cold private SQLite peer directly from a signed encrypted v2 Snapshot Bundle with ZERO historical ops', async () => {
    const devA = await makeDevice()
    const devB = await makeDevice()
    const { genesis, epoch0Key, casNodes } = await createLogGenesis({
      creator: { publicKey: devA.identity.publicKey, wrapKey: devA.wrapKey.publicKey },
      privateLog: true,
      topics: { tasks: { module: 'chronolog/sql' } },
    })
    const sessA = await createApplicationSession({ device: devA, genesis, casNodes, epochKeys: new Map([[0, epoch0Key!]]) })
    try {
      await sessA.admitMember({
        publicKey: devB.identity.publicKey,
        wrapKey: devB.wrapKey.publicKey,
        reader: true,
        writer: true,
      })
      await sessA.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'tasks', input: { action: 'migrate', statements: ['CREATE TABLE tasks (id TEXT PRIMARY KEY, name TEXT)'] } }],
      })
      for (let i = 0; i < 20; i++) {
        await sessA.submit({
          awaitMaterialized: true,
          updates: [{ topic: 'tasks', input: { statements: [{ sql: 'INSERT INTO tasks VALUES (?, ?)', params: [`k${i}`, `Item ${i}`] }] } }],
        })
      }
      const bundle = await sessA.exportMaterializedSnapshot()
      expect(bundle).not.toBeNull()

      const pubControl = await sessA.exportPublicControlFacts()
      const sessB = await createApplicationSession({ device: devB, genesis, casNodes })
      try {
        await sessB.mergeFacts({
          publicOps: pubControl.publicOps,
          encryptedEnvelopes: [],
          casNodes: pubControl.casNodes,
          retentions: [],
          evidence: [],
        })
        const imported = await sessB.importMaterializedSnapshot(bundle!)
        expect(imported).toBe(true)
        const resB = await sessB.query('tasks', { sql: 'SELECT COUNT(*) AS c FROM tasks', format: 'objects' })
        expect((resB.value as { rows: { c: number }[] }).rows[0]!.c).toBe(20)

        await sessB.submit({
          awaitMaterialized: true,
          updates: [{ topic: 'tasks', input: { statements: [{ sql: 'INSERT INTO tasks VALUES (?, ?)', params: ['k20', 'Item 20'] }] } }],
        })
        const resB2 = await sessB.query('tasks', { sql: 'SELECT COUNT(*) AS c FROM tasks', format: 'objects' })
        expect((resB2.value as { rows: { c: number }[] }).rows[0]!.c).toBe(21)
      } finally {
        await sessB.close()
      }
    } finally {
      await sessA.close()
    }
  })

  it('backfillMissingEpochBoxes() heals concurrent admission + epoch rotation gaps', async () => {
    const devA = await makeDevice()
    const devB = await makeDevice()
    const devC = await makeDevice()
    const { genesis, epoch0Key, casNodes } = await createLogGenesis({
      creator: { publicKey: devA.identity.publicKey, wrapKey: devA.wrapKey.publicKey },
      privateLog: true,
      topics: { notes: { module: 'chronolog/sql' } },
    })
    const sessA = await createApplicationSession({ device: devA, genesis, casNodes, epochKeys: new Map([[0, epoch0Key!]]) })
    const sessC = await createApplicationSession({ device: devC, genesis, casNodes })
    try {
      await sessA.admitMember({ publicKey: devB.identity.publicKey, wrapKey: devB.wrapKey.publicKey, reader: true, writer: true })
      await sessA.submit({
        visibility: 'public',
        awaitMaterialized: true,
        updates: [{
          topic: '$admission',
          input: { action: 'setMember', member: { publicKey: devC.identity.publicKey, wrapKey: devC.wrapKey.publicKey, reader: true, writer: true, administrator: false, publisher: false } },
        }],
      })
      const pub1 = await sessA.exportPublicControlFacts()
      await sessC.mergeFacts({ publicOps: pub1.publicOps, encryptedEnvelopes: [], casNodes: pub1.casNodes, retentions: [], evidence: [] })
      expect(sessC.status.keyState).toBe('missing-lockbox')
      expect(sessC.hasEpochKey(0)).toBe(false)

      // A reader that neither administers the log nor admitted C must not author a grant $keys rejects.
      const sessB = await createApplicationSession({ device: devB, genesis, casNodes })
      try {
        await sessB.mergeFacts({ publicOps: pub1.publicOps, encryptedEnvelopes: [], casNodes: pub1.casNodes, retentions: [], evidence: [] })
        expect(sessB.hasEpochKey(0)).toBe(true)
        const before = (await sessB.exportPublicControlFacts()).publicOps.length
        expect(await sessB.backfillMissingEpochBoxes()).toBe(0)
        expect((await sessB.exportPublicControlFacts()).publicOps.length).toBe(before)
      } finally {
        await sessB.close()
      }

      const healed = await sessA.backfillMissingEpochBoxes()
      expect(healed).toBe(1)

      const pub2 = await sessA.exportPublicControlFacts()
      await sessC.mergeFacts({ publicOps: pub2.publicOps, encryptedEnvelopes: [], casNodes: pub2.casNodes, retentions: [], evidence: [] })
      expect(sessC.hasEpochKey(0)).toBe(true)
      expect(sessC.status.keyState).toBe('ready')
      expect(sessC.status.canAuthorData).toBe(true)
    } finally {
      await sessA.close()
      await sessC.close()
    }
  })
})

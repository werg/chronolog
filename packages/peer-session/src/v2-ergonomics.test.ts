import { describe, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { openApplicationDevice } from './device.js'
import { createLogGenesis } from './genesis.js'
import { createApplicationSession } from './runtime.js'

describe('Chronolog v2 ergonomics & platform upgrades', () => {
  it('permits FTS5 and sqlite-vec (vec0) writes directly in chronolog/sql mode:user transactions', async () => {
    const admin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const writer = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
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

    const sAdmin = await createApplicationSession({ device: admin, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sWriter = await createApplicationSession({ device: writer, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      // Admin migrates FTS5 + vec0 tables
      const mig = await sAdmin.command('db:migrate', {
        statements: [
          'CREATE VIRTUAL TABLE docs_fts USING fts5(doc_id UNINDEXED, body)',
          'CREATE VIRTUAL TABLE docs_vec USING vec0(doc_id TEXT PRIMARY KEY, emb FLOAT[4])',
        ],
      }, { operationId: 'mig-fts-vec' })
      expect((await mig.materialized()).outcome).toBe('accepted')

      // Sync to non-admin writer and insert directly in mode:'user' (previously blocked by SQLITE_PRAGMA!)
      await sWriter.mergeFacts(await sAdmin.exportFacts())
      const ins = await sWriter.command('exec', {
        statements: [
          { sql: 'INSERT INTO docs_fts(doc_id, body) VALUES (?, ?)', params: ['d1', 'deterministic local search'] },
          { sql: 'INSERT INTO docs_vec(doc_id, emb) VALUES (?, ?)', params: ['d1', '[1, 0, 0, 0]'] },
        ],
      }, { operationId: 'user-fts-vec-1' })
      expect((await ins.materialized()).outcome).toBe('accepted')

      // Both qualified and unqualified queries work consistently
      const ftsRes = await sWriter.query('db:sql', {
        sql: "SELECT doc_id FROM docs_fts WHERE docs_fts MATCH 'deterministic'",
        format: 'objects',
      })
      expect((ftsRes.value as { rows: unknown[] }).rows).toEqual([{ doc_id: 'd1' }])

      const vecRes = await sWriter.query('sql', {
        sql: "SELECT doc_id FROM docs_vec WHERE emb MATCH '[1,0,0,0]' AND k = 1",
        format: 'objects',
      })
      expect((vecRes.value as { rows: unknown[] }).rows).toEqual([{ doc_id: 'd1' }])
    } finally {
      await sAdmin.close()
      await sWriter.close()
    }
  })

  it('supports blockedAuthors moderation in openMembers and unified session.permissions() summary', async () => {
    const admin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const spammer = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
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

    const sAdmin = await createApplicationSession({ device: admin, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sSpam = await createApplicationSession({ device: spammer, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      const p0 = sAdmin.permissions()
      expect(p0.mode).toBe('open')
      expect(p0.openReaders).toBe(true)
      expect(p0.openWriters).toBe(true)
      expect(p0.blockedAuthors).toEqual([])
      expect(sAdmin.isWriter(spammer.identity.publicKey)).toBe(true)

      // Admin blocks spammer
      const blk = await sAdmin.submit({
        visibility: 'public',
        operationId: 'block-1',
        updates: [{ topic: '$permissions', input: { action: 'blockAuthor', publicKey: spammer.identity.publicKey, reason: 'spam' } }],
      })
      expect((await blk.materialized()).outcome).toBe('accepted')
      expect(sAdmin.permissions().blockedAuthors).toEqual([spammer.identity.publicKey])
      expect(sAdmin.isBlockedAuthor(spammer.identity.publicKey)).toBe(true)
      expect(sAdmin.isWriter(spammer.identity.publicKey)).toBe(false)

      // Spammer's subsequent write is rejected deterministically on both peers
      await sSpam.mergeFacts(await sAdmin.exportFacts())
      const badWrite = await sSpam.submit({
        visibility: 'public',
        operationId: 'spam-1',
        updates: [{ topic: 'db', input: { action: 'exec', statements: ['CREATE TABLE bad (x INT)'] } }],
      })
      expect((await badWrite.materialized()).outcome).toBe('rejected')
      expect((await badWrite.materialized()).rejectionCode).toBe('writer_required')

      // Unblocking restores write access
      const unblk = await sAdmin.submit({
        visibility: 'public',
        operationId: 'unblock-1',
        updates: [{ topic: '$permissions', input: { action: 'unblockAuthor', publicKey: spammer.identity.publicKey } }],
      })
      expect((await unblk.materialized()).outcome).toBe('accepted')
      expect(sAdmin.isBlockedAuthor(spammer.identity.publicKey)).toBe(false)
      expect(sAdmin.isWriter(spammer.identity.publicKey)).toBe(true)
    } finally {
      await sAdmin.close()
      await sSpam.close()
    }
  })

  it('runs concise custom SQLite reducers via chronolog/sqlite-helpers and reads raw CAS payloads via readCasPayload', async () => {
    const dev = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const customSource = `
      import { defineSqlReducer, rowsToObjects } from 'chronolog/sqlite-helpers';
      export default defineSqlReducer({
        setup(db) {
          db.exec('CREATE TABLE IF NOT EXISTS todos (id TEXT PRIMARY KEY, title TEXT NOT NULL, owner TEXT NOT NULL)', [], { mode: 'admin' });
        },
        policies: {
          todos: { insert: 'NEW.owner = actor()', delete: 'OLD.owner = actor()' },
        },
        commands: {
          add: {
            description: 'Add a todo',
            run(db, input) {
              db.exec('INSERT INTO todos(id, title, owner) VALUES (?, ?, actor())', [input.id, input.title], { mode: 'user' });
            },
          },
        },
        queries: {
          list: {
            description: 'List todos',
            run(db) {
              return rowsToObjects(db.query('SELECT id, title, owner FROM todos ORDER BY id', []));
            },
          },
        },
      });
    `
    const created = await createLogGenesis({
      creator: {
        publicKey: dev.identity.publicKey,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: true,
      },
      privateLog: false,
      imports: { '@app/todos': customSource },
      topics: { todos: { module: '@app/todos' } },
    })

    const session = await createApplicationSession({ device: dev, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      const add = await session.command('add', { id: 't1', title: 'Ship helpers' }, { operationId: 'todo-1' })
      expect((await add.materialized()).outcome).toBe('accepted')
      const listed = await session.query('list', {})
      expect(listed.value).toEqual([{ id: 't1', title: 'Ship helpers', owner: dev.identity.publicKey }])

      // Automatic schema introspection works on defineSqlReducer topics too
      const schema = await session.query('todos:schema', {})
      expect((schema.value as { tables: Array<{ name: string }> }).tables.map(t => t.name)).toContain('todos')

      // readCasPayload decodes module bytes cleanly without internal decodeCasNode
      const reducers = session.topic('$reducers') as { imports: Record<string, string> }
      const hash = reducers.imports['@app/todos']!.slice('cas:sha256-'.length)
      const decoded = await session.readCasPayload(hash, 'public')
      expect(decoded).not.toBeNull()
      expect(new TextDecoder().decode(decoded!.payload)).toContain('defineSqlReducer')
    } finally {
      await session.close()
    }
  })

  it('supports content.putStream, readStream, pin/unpin, stats, and LRU pruneCache', async () => {
    const dev = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createLogGenesis({
      creator: {
        publicKey: dev.identity.publicKey,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: true,
      },
      privateLog: true,
      topics: { db: { module: 'chronolog/sql' } },
    })
    const session = await createApplicationSession({
      device: dev,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys: new Map([[0, created.epoch0Key!]]),
    })
    try {
      // Stream a 150 KiB private blob (> 2 chunks) without buffering whole file
      const total = 150_000
      const full = new Uint8Array(total)
      for (let i = 0; i < total; i++) full[i] = i & 0xff
      async function* chunkGen() {
        for (let off = 0; off < total; off += 25_000) {
          yield full.subarray(off, Math.min(total, off + 25_000))
        }
      }
      const privRef = await session.content.putStream(chunkGen(), {
        visibility: 'private',
        mediaType: 'application/octet-stream',
        totalBytes: total,
      })
      const streamedOut: Uint8Array[] = []
      for await (const chunk of session.content.readStream(privRef)) streamedOut.push(chunk)
      const reassembled = new Uint8Array(streamedOut.reduce((s, c) => s + c.byteLength, 0))
      let pos = 0
      for (const c of streamedOut) { reassembled.set(c, pos); pos += c.byteLength }
      expect(reassembled).toEqual(full)

      // Public blobs + pin + LRU pruneCache
      const b1 = await session.content.put(new Uint8Array(40_000).fill(1), { visibility: 'public' })
      await new Promise(r => setTimeout(r, 5))
      const b2 = await session.content.put(new Uint8Array(40_000).fill(2), { visibility: 'public' })
      await session.content.pin(privRef)
      await session.content.pin(b1)
      expect(await session.content.isPinned(b1)).toBe(true)

      const before = await session.content.stats()
      expect(before.publicBlobs).toBe(2)
      expect(before.privateItems).toBe(1)
      expect(before.pinnedCount).toBe(2)
      expect(before.totalBytes).toBe(230_000)

      // Prune down to 190_000: only unpinned b2 (40_000) should be evicted; pinned b1 & privRef stay!
      const pruned = await session.content.pruneCache({ maxBytes: 190_000 })
      expect(pruned.evictedCount).toBe(1)
      expect(pruned.evictedBytes).toBe(40_000)
      expect(await session.content.get(b1, { localOnly: true })).not.toBeNull()
      expect(await session.content.get(b2, { localOnly: true })).toBeNull()
      expect(await session.content.get(privRef)).toEqual(full)
    } finally {
      await session.close()
    }
  })
})

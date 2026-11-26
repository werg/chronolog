import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/canonical'
import { MemoryBytesStore } from '@chronolog/records'
import { createChainGenesis } from './genesis.js'
import { openApplicationDevice } from './device.js'
import { openNativeDevice } from './native.js'
import { createApplicationSession } from './runtime.js'
import { createFramedPeerConnectionPair } from './network-wire.js'
import { createScopedApplicationTools } from './tools.js'

const closes: Array<() => Promise<void>> = []
afterEach(async () => {
  for (const close of closes.splice(0).reverse()) {
    try { await close() } catch { /* ignore cleanup errors */ }
  }
})

const KV_REDUCER = `
export default {
  reduce(state, tx) {
    const map = state && typeof state === 'object' ? { ...state } : {};
    const { action, key, value } = tx.payload || {};
    if (action === 'set') {
      map[key] = { value, author: tx.author, ts: tx.authorTimestampMs };
      return { ok: true, state: map, events: [{ topic: 'kv.set', payload: { key, value } }] };
    }
    return { ok: false, code: 'unknown_action' };
  },
  query(state, input) {
    const map = state && typeof state === 'object' ? state : {};
    if (input && input.key) return map[input.key] ?? null;
    return map;
  },
  describe() {
    return {
      commands: [{
        name: 'set',
        description: 'Set a key/value entry',
        input: { type: 'object', properties: { key: { type: 'string' }, value: { type: 'string' } }, required: ['key', 'value'] },
      }],
      queries: [{
        name: 'get',
        description: 'Get entries',
        input: { type: 'object', properties: { key: { type: 'string' } } },
      }],
    };
  },
};
`.trimStart()

const SQL_TASKS_REDUCER = `
import { openDb } from 'chronolog:sqlite';
import { applyRls } from 'chronolog/rls';

export default {
  reduce(state, tx) {
    const db = openDb(state);
    db.exec('CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL)', [], { mode: 'admin' });
    applyRls(db, {
      tasks: {
        insert: 'NEW.owner = actor()',
        update: 'OLD.owner = actor() AND NEW.owner = actor()',
        delete: 'OLD.owner = actor()',
      },
    });
    const p = tx.payload || {};
    if (p.action === 'addTask') {
      db.exec('INSERT INTO tasks (id, owner, title) VALUES (?, actor(), ?)', [p.id, p.title], { mode: 'user' });
      return { ok: true, state: db.commit(), events: [{ topic: 'task.added', payload: { id: p.id, title: p.title } }] };
    }
    if (p.action === 'renameTask') {
      db.exec('UPDATE tasks SET title = ? WHERE id = ?', [p.title, p.id], { mode: 'user' });
      return { ok: true, state: db.commit(), events: [{ topic: 'task.renamed', payload: { id: p.id, title: p.title } }] };
    }
    return { ok: false, code: 'unknown_action' };
  },
  query(state, input) {
    const db = openDb(state);
    const hasTable = db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'").rows.length > 0;
    if (!hasTable) return [];
    const res = db.query('SELECT id, owner, title FROM tasks ORDER BY id');
    return res.rows.map(r => ({ id: r[0], owner: r[1], title: r[2] }));
  },
  describe() {
    return {
      commands: [
        { name: 'addTask', description: 'Create a task', input: { type: 'object', properties: { id: { type: 'string' }, title: { type: 'string' } }, required: ['id', 'title'] } },
        { name: 'renameTask', description: 'Rename your own task', input: { type: 'object', properties: { id: { type: 'string' }, title: { type: 'string' } }, required: ['id', 'title'] } },
      ],
      queries: [
        { name: 'listTasks', description: 'List all tasks', input: { type: 'object', properties: {} } },
      ],
    };
  },
};
`.trimStart()

describe('Chronolog v2 ApplicationSession (Gate 3)', () => {
  it('authors durably offline with node:sqlite NativeBytesStore, reopens cleanly, and converges over P2P', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'chronolog-v2-offline-'))
    const pathA = join(dir, 'a.sqlite')
    const pathB = join(dir, 'b.sqlite')
    try {
      const devA = await openNativeDevice({ path: pathA, create: true })
      const devB = await openNativeDevice({ path: pathB, create: true })
      const created = await createChainGenesis({
        creator: { publicKey: devA.identity.publicKey, wrapKey: devA.wrapKey.publicKey, reader: true, writer: true, administrator: true },
        members: [{ publicKey: devB.identity.publicKey, wrapKey: devB.wrapKey.publicKey, reader: true, writer: true }],
        privateChain: true,
        imports: { 'app/kv': KV_REDUCER },
        topics: { kv: { module: 'app/kv', initialState: {} } },
      })

      const sessA = await createApplicationSession({
        device: devA,
        genesis: created.genesisBytes,
        casNodes: created.casNodes,
        epochKeys: new Map([[0, created.epoch0Key!]]),
      })
      const op1 = await sessA.command('set', { key: 'hello', value: 'world' }, { authorTimestampMs: 100n, operationId: 'op-1' })
      expect((await op1.materialized()).outcome).toBe('accepted')
      await sessA.close()

      // Reopen A purely from disk (zero genesis or epochKeys passed!)
      const devA2 = await openNativeDevice({ path: pathA })
      const sessA2 = await createApplicationSession({ device: devA2, chainId: created.chainId })
      closes.push(() => sessA2.close())
      expect((await sessA2.query('get', { key: 'hello' })).value).toMatchObject({ value: 'world' })

      // Open B and connect via authenticated P2P wire
      const sessB = await createApplicationSession({
        device: devB,
        genesis: created.genesisBytes,
        casNodes: created.casNodes,
        epochKeys: new Map([[0, created.epoch0Key!]]),
      })
      closes.push(() => sessB.close())
      const op2 = await sessB.command('set', { key: 'fromB', value: 'peer' }, { authorTimestampMs: 50n, operationId: 'op-2' })
      expect((await op2.materialized()).outcome).toBe('accepted')

      const [cA, cB] = createFramedPeerConnectionPair()
      const [linkA, linkB] = await Promise.all([
        sessA2.connectPeer({ connection: cA }),
        sessB.connectPeer({ connection: cB }),
      ])
      await Promise.all([linkA.synchronize(), linkB.synchronize()])

      expect(sessA2.revision().stateRoot).toBe(sessB.revision().stateRoot)
      expect(sessA2.revision().digest).toBe(sessB.revision().digest)
      expect((await sessA2.query('get', { key: 'fromB' })).value).toMatchObject({ value: 'peer' })
      expect((await sessB.query('get', { key: 'hello' })).value).toMatchObject({ value: 'world' })
      await Promise.all([linkA.close(), linkB.close()])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('fresh-device admission after multiple epoch rotations unseals historical epochs and replays full history', async () => {
    const devA = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devFresh = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createChainGenesis({
      creator: { publicKey: devA.identity.publicKey, wrapKey: devA.wrapKey.publicKey, reader: true, writer: true, administrator: true },
      privateChain: true,
      imports: { 'app/kv': KV_REDUCER },
      topics: { kv: { module: 'app/kv', initialState: {} } },
    })
    const sessA = await createApplicationSession({
      device: devA,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys: new Map([[0, created.epoch0Key!]]),
    })
    closes.push(() => sessA.close())

    // Seed epoch 0 in $keys via rotateEpoch (currentEpoch -1 -> 0) and write in epoch 0, 1, 2
    await sessA.rotateEpoch({ newEpochKey: created.epoch0Key!, authorTimestampMs: 10n })
    await (await sessA.command('set', { key: 'e0', value: 'v0' }, { authorTimestampMs: 20n })).materialized()
    await sessA.rotateEpoch({ authorTimestampMs: 30n })
    await (await sessA.command('set', { key: 'e1', value: 'v1' }, { authorTimestampMs: 40n })).materialized()
    await sessA.rotateEpoch({ authorTimestampMs: 50n })
    await (await sessA.command('set', { key: 'e2', value: 'v2' }, { authorTimestampMs: 60n })).materialized()

    // Admit fresh device (which has ZERO prior epoch keys!)
    await (await sessA.admitMember({
      publicKey: devFresh.identity.publicKey,
      wrapKey: devFresh.wrapKey.publicKey,
      reader: true,
      writer: true,
      authorTimestampMs: 70n,
    })).materialized()

    const sessFresh = await createApplicationSession({
      device: devFresh,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
    })
    closes.push(() => sessFresh.close())

    // Merge facts from A: fresh device unseals epochs 0, 1, 2 via HPKE and decrypts all history!
    await sessFresh.mergeFacts(await sessA.exportFacts())
    expect(sessFresh.revision().stateRoot).toBe(sessA.revision().stateRoot)
    expect((await sessFresh.query('get', { key: 'e0' })).value).toMatchObject({ value: 'v0' })
    expect((await sessFresh.query('get', { key: 'e1' })).value).toMatchObject({ value: 'v1' })
    expect((await sessFresh.query('get', { key: 'e2' })).value).toMatchObject({ value: 'v2' })
  })

  it('reconnect rewrapping preserves exact opId/timestamp/signature under new epoch and syncs via envelopeDigest', async () => {
    const devA = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devB = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devRevoked = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createChainGenesis({
      creator: { publicKey: devA.identity.publicKey, wrapKey: devA.wrapKey.publicKey, reader: true, writer: true, administrator: true },
      members: [
        { publicKey: devB.identity.publicKey, wrapKey: devB.wrapKey.publicKey, reader: true, writer: true },
        { publicKey: devRevoked.identity.publicKey, wrapKey: devRevoked.wrapKey.publicKey, reader: true, writer: true },
      ],
      privateChain: true,
      imports: { 'app/kv': KV_REDUCER },
      topics: { kv: { module: 'app/kv', initialState: {} } },
    })

    const sessA = await createApplicationSession({ device: devA, genesis: created.genesisBytes, casNodes: created.casNodes, epochKeys: new Map([[0, created.epoch0Key!]]) })
    const sessB = await createApplicationSession({ device: devB, genesis: created.genesisBytes, casNodes: created.casNodes, epochKeys: new Map([[0, created.epoch0Key!]]) })
    closes.push(() => sessA.close(), () => sessB.close())

    // Initialize epoch 0 in $keys
    await sessA.rotateEpoch({ newEpochKey: created.epoch0Key!, authorTimestampMs: 10n })
    await sessB.mergeFacts(await sessA.exportFacts())

    // B goes offline and writes at t=105 under epoch 0
    const offlineOp = await sessB.command('set', { key: 'offline', value: 'preserved' }, { authorTimestampMs: 105n, operationId: 'offline-b' })
    const originalOpId = offlineOp.id
    expect((await offlineOp.materialized()).outcome).toBe('accepted')

    // Meanwhile A revokes devRevoked and rotates to epoch 1 at t=100
    await (await sessA.removeMember(devRevoked.identity.publicKey, { authorTimestampMs: 100n })).materialized()
    expect(sessA.currentEpoch()).toBe(1)

    // B reconnects and merges A's rotation: B unseals epoch 1 and automatically rewraps offlineOp under epoch 1!
    await sessB.mergeFacts(await sessA.exportFacts())
    expect(sessB.currentEpoch()).toBe(1)

    // Sync B -> A: A receives the epoch-1 rewrap with identical opId and converges!
    await sessA.mergeFacts(await sessB.exportFacts())
    expect(sessA.revision().stateRoot).toBe(sessB.revision().stateRoot)
    expect((await sessA.query('get', { key: 'offline' })).value).toMatchObject({ value: 'preserved' })
    expect(sessA.inspectOperation(originalOpId).materialized?.outcome).toBe('accepted')
  })

  it('supports none -> P1 finality bootstrap, checkpoint creation, and checkpoint-plus-suffix revision parity', async () => {
    const devA = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devJoiner = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createChainGenesis({
      creator: { publicKey: devA.identity.publicKey, wrapKey: devA.wrapKey.publicKey, reader: true, writer: true, administrator: true, finalizer: true },
      members: [{ publicKey: devJoiner.identity.publicKey, wrapKey: devJoiner.wrapKey.publicKey, reader: true, writer: true }],
      privateChain: true,
      imports: { 'app/kv': KV_REDUCER },
      topics: { kv: { module: 'app/kv', initialState: {} } },
    })

    const sessA = await createApplicationSession({ device: devA, genesis: created.genesisBytes, casNodes: created.casNodes, epochKeys: new Map([[0, created.epoch0Key!]]) })
    closes.push(() => sessA.close())

    // Start in finality: none
    await expect(sessA.readView({ view: 'final' })).rejects.toMatchObject({ code: 'FINALITY_UNSUPPORTED' })

    await (await sessA.command('set', { key: 'k1', value: 'v1' }, { authorTimestampMs: 10n })).materialized()
    // Activate signed-frontier finality effective after t=20 (none -> P1 bootstrap!)
    await (await sessA.scheduleFinality({
      effectiveAfterMs: 20n,
      policy: { kind: 'signed-frontier', signer: devA.identity.publicKey },
      authorTimestampMs: 15n,
    })).materialized()

    await (await sessA.command('set', { key: 'k2', value: 'v2' }, { authorTimestampMs: 25n })).materialized()
    const { checkpoint, snapshot } = await sessA.finality.createCheckpoint({ throughMs: 30n })
    expect(sessA.finality.status().closedThroughMs).toBe(30n)

    // Write a suffix op after the checkpoint
    const suffixOp = await sessA.command('set', { key: 'k3', value: 'v3' }, { authorTimestampMs: 40n })
    await suffixOp.materialized()

    // Joiner bootstraps from checkpoint snapshot + replays ONLY the suffix op (t=40)
    const sessJoiner = await createApplicationSession({ device: devJoiner, genesis: created.genesisBytes, casNodes: created.casNodes, epochKeys: new Map([[0, created.epoch0Key!]]) })
    closes.push(() => sessJoiner.close())

    // Give joiner the seenOpsRoot CAS node + checkpoint snapshot
    await sessJoiner.mergeFacts({ publicOps: [], encryptedEnvelopes: [], casNodes: (await sessA.exportFacts()).casNodes, retentions: [], checkpoints: [] })
    await sessJoiner.finality.bootstrapFromCheckpoint(checkpoint, snapshot)

    // Now feed ONLY the suffix op envelope
    const allFacts = await sessA.exportFacts()
    const suffixEnv = allFacts.encryptedEnvelopes.at(-1)!
    await sessJoiner.mergeFacts({ publicOps: [], encryptedEnvelopes: [suffixEnv], casNodes: [], retentions: [], checkpoints: [] })

    // Checkpoint + suffix produces IDENTICAL stateRoot AND revision.digest to full replay!
    expect(sessJoiner.revision().stateRoot).toBe(sessA.revision().stateRoot)
    expect(sessJoiner.revision().historyDigest).toBe(sessA.revision().historyDigest)
    expect(sessJoiner.revision().digest).toBe(sessA.revision().digest)
  })

  it('publishes signed UI releases to $publications, matches blindHostMode, and instantly revokes signal policy', async () => {
    const devAdmin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devMember = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devHost = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createChainGenesis({
      creator: { publicKey: devAdmin.identity.publicKey, wrapKey: devAdmin.wrapKey.publicKey, reader: true, writer: true, administrator: true, publisher: true },
      members: [{ publicKey: devMember.identity.publicKey, wrapKey: devMember.wrapKey.publicKey, reader: true, writer: true }],
      privateChain: true,
      imports: { 'app/kv': KV_REDUCER },
      topics: { kv: { module: 'app/kv', initialState: {} } },
    })

    const admin = await createApplicationSession({ device: devAdmin, genesis: created.genesisBytes, casNodes: created.casNodes, epochKeys: new Map([[0, created.epoch0Key!]]) })
    const host = await createApplicationSession({ device: devHost, genesis: created.genesisBytes, casNodes: created.casNodes, blindHostMode: true })
    closes.push(() => admin.close(), () => host.close())

    await (await admin.command('set', { key: 'secret', value: 'top-secret' }, { authorTimestampMs: 10n })).materialized()
    await (await admin.publishRelease({
      entry: 'index.html',
      files: [{ path: 'index.html', bytes: utf8('<h1>Chronolog v2</h1>'), type: 'text/html' }],
      authorTimestampMs: 20n,
    })).materialized()

    // Blind host receives ONLY blind facts (no private CAS, no epoch keys) and derives identical $publications!
    await host.mergeFacts(await admin.exportFacts({ includePrivateCas: false }))
    expect(host.topic('$publications')).toEqual(admin.topic('$publications'))
    expect(host.topic('kv')).toBeNull()

    // Signal policy allows member before removal, rejects immediately after removal!
    const member = await createApplicationSession({ device: devMember, genesis: created.genesisBytes, casNodes: created.casNodes, epochKeys: new Map([[0, created.epoch0Key!]]) })
    closes.push(() => member.close())
    const [c1, c2] = createFramedPeerConnectionPair()
    const [l1, l2] = await Promise.all([admin.connectPeer({ connection: c1 }), member.connectPeer({ connection: c2 })])
    const received: unknown[] = []
    const sigAbort = new AbortController()
    const listening = (async () => {
      for await (const sig of admin.signals.subscribe({ topics: ['cursor'], signal: sigAbort.signal })) {
        received.push(sig.payload)
      }
    })()
    await member.signals.send('cursor', { x: 42 })
    await expect.poll(() => received).toEqual([{ x: 42 }])

    // Revoke member: signal policy cache invalidates immediately on stateRoot change
    await (await admin.removeMember(devMember.identity.publicKey, { authorTimestampMs: 30n })).materialized()
    await member.signals.send('cursor', { x: 99 })
    await new Promise(r => setTimeout(r, 50))
    expect(received).toEqual([{ x: 42 }])

    sigAbort.abort()
    await listening.catch(() => undefined)
    await Promise.all([l1.close(), l2.close()])
  })

  it('runs SQLite-CAS + chronolog/rls end-to-end via session.command/query/describe/scopedTools and CAS GC', async () => {
    const devA = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devB = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createChainGenesis({
      creator: { publicKey: devA.identity.publicKey, wrapKey: devA.wrapKey.publicKey, reader: true, writer: true, administrator: true },
      members: [{ publicKey: devB.identity.publicKey, wrapKey: devB.wrapKey.publicKey, reader: true, writer: true }],
      privateChain: true,
      imports: { 'app/tasks': SQL_TASKS_REDUCER },
      topics: { tasks: { module: 'app/tasks', initialState: null } },
    })

    const sessA = await createApplicationSession({ device: devA, genesis: created.genesisBytes, casNodes: created.casNodes, epochKeys: new Map([[0, created.epoch0Key!]]) })
    const sessB = await createApplicationSession({ device: devB, genesis: created.genesisBytes, casNodes: created.casNodes, epochKeys: new Map([[0, created.epoch0Key!]]) })
    closes.push(() => sessA.close(), () => sessB.close())

    // Describe comes straight from the in-chain reducer (no separate domain.js!)
    const description = await sessA.describe()
    expect(description.commands.map(c => c.name)).toEqual(['addTask', 'renameTask'])
    expect(description.queries.map(q => q.name)).toEqual(['listTasks'])

    // Scoped tools work directly against session.describe()
    const tools = createScopedApplicationTools(sessA, { description })
    await tools.execute({ kind: 'command', name: 'addTask', input: { id: 't1', title: 'Ship v2' }, operationId: 'tool-1' }, { caller: 'mcp-agent' })
    expect((await sessA.query('listTasks')).value).toEqual([{ id: 't1', owner: devA.identity.publicKey, title: 'Ship v2' }])

    // Sync to B; B attempts to rename A's task -> rejected by chronolog/rls BEFORE UPDATE trigger!
    await sessB.mergeFacts(await sessA.exportFacts())
    const badRename = await sessB.command('renameTask', { id: 't1', title: 'Hijacked' }, { authorTimestampMs: BigInt(Date.now() + 100) })
    const res = await badRename.materialized()
    expect(res.outcome).toBe('rejected')
    expect((await sessB.query('listTasks')).value).toEqual([{ id: 't1', owner: devA.identity.publicKey, title: 'Ship v2' }])

    // CAS garbage collection keeps live SQLite page tree intact!
    const gc = await sessA.collectGarbage()
    expect(gc.kept).toBeGreaterThan(0)
    expect((await sessA.query('listTasks')).value).toEqual([{ id: 't1', owner: devA.identity.publicKey, title: 'Ship v2' }])
  })
})

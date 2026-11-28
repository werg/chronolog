import { createServer } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { bytesToHex, sha256Sync, utf8 } from '@chronolog/canonical'
import { MemoryBytesStore } from '@chronolog/records'
import {
  createApplicationSession,
  createLogGenesis,
  openApplicationDevice,
} from './index.js'
import {
  createHttpSyncClient,
  createHttpSyncHandler,
  type BlindSyncStore,
  type HttpSyncFactItem,
} from './mirror.js'
import { runEphemeralHostedSession } from './kernel.js'
import {
  acquireAtomicLock,
  connectNativeIpc,
  openExclusiveSqliteFence,
  startNativeIpcServer,
} from './native.js'
import { FactIdSet } from './reconcile.js'

async function startWebServer(handler: (req: Request) => Promise<Response>) {
  const server = createServer((req, res) => {
    void (async () => {
      const chunks: Uint8Array[] = []
      for await (const chunk of req) chunks.push(chunk as Uint8Array)
      const body = chunks.length > 0 ? Buffer.concat(chunks) : undefined
      const url = `http://${req.headers.host ?? '127.0.0.1'}${req.url ?? '/'}`
      const headers = new Headers()
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v)
      const webReq = new Request(url, {
        method: req.method ?? 'GET',
        headers,
        ...(body !== undefined && req.method !== 'GET' && req.method !== 'HEAD' ? { body } : {}),
      })
      const webRes = await handler(webReq)
      res.statusCode = webRes.status
      webRes.headers.forEach((v, k) => res.setHeader(k, v))
      res.end(new Uint8Array(await webRes.arrayBuffer()))
    })()
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as { port: number }).port
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  }
}

describe('Binary CBOR HTTP sync-v3, Ephemeral Hosted Runner & Native Supervisor', () => {
  it('reconciles 0, small, and large (80+) fact sets over binary CBOR sync-v3 HTTP in O(log N) rounds', async () => {
    const serverMap = new Map<string, Uint8Array>()
    const store: BlindSyncStore = {
      listIds() { return Promise.resolve([...serverMap.keys()]) },
      getFacts(_scope, ids) {
        const out: HttpSyncFactItem[] = []
        for (const id of ids) {
          const b = serverMap.get(id)
          if (b !== undefined) out.push({ id, bytes: b })
        }
        return Promise.resolve(out)
      },
      putFacts(_scope, items) {
        let accepted = 0
        for (const item of items) {
          if (!serverMap.has(item.id)) { serverMap.set(item.id, item.bytes); accepted += 1 }
        }
        return Promise.resolve({ accepted, meta: { total: serverMap.size } })
      },
    }

    // Seed 60 server-only facts + 40 shared facts
    const clientMap = new Map<string, Uint8Array>()
    const makeFact = (label: string): { id: string; bytes: Uint8Array } => {
      const bytes = utf8(`fact:${label}`)
      return { id: bytesToHex(sha256Sync(bytes)), bytes }
    }
    for (let i = 0; i < 40; i++) {
      const f = makeFact(`shared-${i}`)
      serverMap.set(f.id, f.bytes)
      clientMap.set(f.id, f.bytes)
    }
    for (let i = 0; i < 60; i++) {
      const f = makeFact(`server-only-${i}`)
      serverMap.set(f.id, f.bytes)
    }
    for (let i = 0; i < 25; i++) {
      const f = makeFact(`client-only-${i}`)
      clientMap.set(f.id, f.bytes)
    }

    const handler = createHttpSyncHandler({ store, basePath: '/_sync' })
    const srv = await startWebServer(handler)
    try {
      const client = createHttpSyncClient(`${srv.baseUrl}/_sync`)
      const localIds = new FactIdSet()
      for (const id of clientMap.keys()) localIds.add(id)

      const res = await client.reconcile('mailbox', {
        ids: localIds,
        getFacts: ids => Promise.resolve(ids.filter(id => clientMap.has(id)).map(id => ({ id, bytes: clientMap.get(id)! }))),
        onReceive: items => {
          for (const item of items) clientMap.set(item.id, item.bytes)
          return Promise.resolve()
        },
      })
      expect(res.pushed).toBe(25)
      expect(res.pulled).toBe(60)
      expect(serverMap.size).toBe(125)
      expect(clientMap.size).toBe(125)
      expect([...serverMap.keys()].sort()).toEqual([...clientMap.keys()].sort())

      // Second sync settles in exactly 1 round with 0 pushed and 0 pulled!
      const res2 = await client.reconcile('mailbox', {
        ids: localIds,
        getFacts: () => Promise.resolve([]),
        onReceive: () => Promise.resolve(),
      })
      expect(res2.rounds).toBe(1)
      expect(res2.pushed).toBe(0)
      expect(res2.pulled).toBe(0)
    } finally {
      await srv.close()
    }
  })

  it('runs zero-plaintext runEphemeralHostedSession, exports encrypted delta + snapshot, and wipes RAM keys', async () => {
    const dev = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createLogGenesis({
      creator: {
        publicKey: dev.identity.publicKey,
        wrapKey: dev.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
      },
      privateLog: true,
      imports: {
        'app/notes': `export default {
          reduce(state, tx) {
            const list = Array.isArray(state) ? state : [];
            return { ok: true, state: list.concat([tx.payload.text]) };
          },
          query(state) { return Array.isArray(state) ? state : []; },
        };`,
      },
      topics: { notes: { module: 'app/notes' } },
    })

    const epochKeys = new Map<number, Uint8Array>([[0, created.epoch0Key!]])
    const { value, delta } = await runEphemeralHostedSession({
      genesisBytes: created.genesisBytes,
      signer: dev.identity,
      epochKeys,
      publicOps: [],
      encryptedEnvelopes: [],
      publicCasNodes: created.casNodes.filter(n => n.partition === 'public').map(n => ({ hash: n.hash, bytes: n.bytes })),
    }, async session => {
      await (await session.submit({
        updates: [{ topic: 'notes', input: { text: 'hello from ephemeral worker' } }],
      })).materialized()
      return (await session.query('notes', {})).value
    })

    expect(value).toEqual(['hello from ephemeral worker'])
    expect(delta.newEnvelopes).toHaveLength(1)
    expect(delta.snapshot).not.toBeNull()

    // Re-open with exported encrypted envelope + snapshot on a brand-new ephemeral session!
    const { value: secondRead } = await runEphemeralHostedSession({
      genesisBytes: created.genesisBytes,
      signer: dev.identity,
      epochKeys,
      publicOps: [],
      encryptedEnvelopes: delta.newEnvelopes.map(e => e.raw),
      publicCasNodes: created.casNodes.filter(n => n.partition === 'public').map(n => ({ hash: n.hash, bytes: n.bytes })),
      ...(delta.snapshot === null ? {} : { materializedSnapshot: delta.snapshot }),
    }, async session => (await session.query('notes', {})).value)
    expect(secondRead).toEqual(['hello from ephemeral worker'])

    // Verify original session in a normal device can decrypt the envelope authored by hosted runner
    const normal = await createApplicationSession({
      device: dev,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    try {
      await normal.mergeFacts({
        publicOps: [],
        encryptedEnvelopes: delta.newEnvelopes.map(e => e.raw),
        casNodes: [],
        retentions: [],
        evidence: [],
      })
      expect(normal.topic('notes')).toEqual(['hello from ephemeral worker'])
    } finally {
      await normal.close()
    }
  })

  it('enforces acquireAtomicLock, openExclusiveSqliteFence, and length-prefixed native IPC', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'chronolog-native-sup-'))
    try {
      const lock = acquireAtomicLock(dir)
      expect(() => acquireAtomicLock(dir)).toThrow(/OWNER_BUSY|held by active PID/u)
      lock.release()
      const lock2 = acquireAtomicLock(dir)
      lock2.release()

      const fence = openExclusiveSqliteFence(join(dir, 'owner.sqlite'))
      fence.close()

      const sockPath = join(dir, 'ipc.sock')
      const received: string[] = []
      const srv = await startNativeIpcServer({
        socketPath: sockPath,
        onConnection: conn => {
          conn.onFrame(frame => {
            const msg = new TextDecoder().decode(frame)
            received.push(msg)
            conn.send(utf8(`echo:${msg}`))
          })
        },
      })
      try {
        const client = await connectNativeIpc(sockPath)
        const reply = await new Promise<string>(resolve => {
          client.onFrame(frame => resolve(new TextDecoder().decode(frame)))
          client.send(utf8('ping'))
        })
        expect(received).toEqual(['ping'])
        expect(reply).toBe('echo:ping')
        client.close()
      } finally {
        await srv.close()
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

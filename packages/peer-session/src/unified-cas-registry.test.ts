import { createServer } from 'node:http'
import { describe, expect, it } from 'vitest'
import { bytesToHex, utf8 } from '@chronolog/canonical'
import { computeBlobDagHash, MemoryBytesStore, parseCasRef } from '@chronolog/records'
import { packReducers, RegistryClient } from '@chronolog/pack'
import {
  createApplicationSession,
  createLogGenesis,
  createRegistryGenesis,
  openApplicationDevice,
} from './index.js'
import { createFramedPeerConnectionPair } from './network-wire.js'

async function generateEd25519KeyPair(): Promise<{ readonly privateKey: CryptoKey; readonly publicKeyBytes: Uint8Array }> {
  const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  return { privateKey: kp.privateKey, publicKeyBytes }
}

function newMemoryDevice() {
  return openApplicationDevice({ store: new MemoryBytesStore(), create: true })
}

describe('Unified CAS, subgraph peer pull, HTTP CAS mirrors, private app code, Registry Chronolog & $mounts', () => {
  it('unifies session.cas and session.content under one Merkle-DAG hash space (public & private encrypted blobs)', async () => {
    const dev = await newMemoryDevice()
    const created = await createLogGenesis({
      creator: { publicKey: dev.identity.publicKey, wrapKey: dev.wrapKey.publicKey },
      privateLog: true,
    })
    const session = await createApplicationSession({
      device: dev,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys: new Map([[0, created.epoch0Key!]]),
    })
    try {
      // 1. Public blob in session.content lives directly in session.cas under chronolog-blob/v1!
      const bytes = new Uint8Array(140_000).map((_, i) => (i * 13) & 0xff)
      const info = await session.content.putBlob(bytes)
      expect(info.hash).toBe(computeBlobDagHash(bytes))
      expect(await session.cas.get(info.hash, 'public')).not.toBeNull()
      expect(await session.content.getBlob(info.hash)).toEqual(bytes)

      // 2. publishRelease stores release files using the exact same CAS hash!
      const html = utf8('<h1>Unified CAS</h1>')
      await session.publishRelease({
        entry: 'index.html',
        files: [{ path: 'index.html', bytes: html, type: 'text/html' }],
      })
      const pubHash = computeBlobDagHash(html)
      expect(await session.content.getBlob(pubHash)).toEqual(html)
      expect(await session.cas.get(pubHash, 'public')).not.toBeNull()

      // 3. Private encrypted blob stores its encrypted chunks as CasNodes in session.cas!
      const secret = utf8('top secret encrypted attachment')
      const encRef = await session.content.put(secret, { visibility: 'private', mediaType: 'text/plain' })
      expect(await session.content.get(encRef)).toEqual(secret)
    } finally {
      await session.close()
    }
  })

  it('pulls a newly installed multi-file package DAG in one cas-want subgraph round-trip over peer link', async () => {
    const devA = await newMemoryDevice()
    const devB = await newMemoryDevice()
    const created = await createLogGenesis({
      creator: { publicKey: devA.identity.publicKey, wrapKey: devA.wrapKey.publicKey },
      members: [{ publicKey: devB.identity.publicKey, wrapKey: devB.wrapKey.publicKey, reader: true, writer: true }],
      privateLog: false,
    })
    const sessA = await createApplicationSession({ device: devA, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sessB = await createApplicationSession({ device: devB, genesis: created.genesisBytes, casNodes: created.casNodes })
    const [connA, connB] = createFramedPeerConnectionPair()
    try {
      // Peer A installs a multi-file package with a relative import live at runtime!
      const packed = await packReducers({
        entries: {
          '@app/notes': {
            bundle: false,
            files: {
              'index.ts': `
                import { clean } from './clean.js';
                export default {
                  reduce(state: string[] | null, tx: { payload: { text: string } }) {
                    return { ok: true, state: [...(state || []), clean(tx.payload.text)] };
                  },
                };
              `,
              'clean.ts': `export function clean(s: string): string { return s.trim().toUpperCase(); }`,
            },
          },
        },
      })
      await sessA.installPackage(
        { ref: packed.entries['@app/notes']!.pkgRef, casNodes: packed.casNodes },
        { alias: '@app/notes', topics: { notes: {} } },
      )
      await sessA.submit({
        visibility: 'public',
        awaitMaterialized: true,
        updates: [{ topic: 'notes', input: { text: '  hello subgraph!  ' } }],
      })

      // Connect Peer B (which has NONE of @app/notes's CAS nodes yet!)
      const [linkA, linkB] = await Promise.all([
        sessA.connectPeer({ connection: connA }),
        sessB.connectPeer({ connection: connB }),
      ])
      await Promise.all([linkA.synchronize(), linkB.synchronize()])
      expect(sessB.topic('notes')).toEqual(['HELLO SUBGRAPH!'])
      await Promise.all([linkA.close(), linkB.close()])
    } finally {
      await sessA.close()
      await sessB.close()
    }
  })

  it('keeps private app package bytes hidden from blind hosts while deriving identical control state, and fetches missing public CAS from untrusted HTTP mirrors', async () => {
    const devAdmin = await newMemoryDevice()
    const devBlind = await newMemoryDevice()

    const created = await createLogGenesis({
      creator: { publicKey: devAdmin.identity.publicKey, wrapKey: devAdmin.wrapKey.publicKey },
      privateLog: true,
      packages: {
        '@secret/logic': {
          partition: 'private',
          files: {
            'index.js': 'export default { reduce(s, tx) { return { ok: true, state: (s || 0) + tx.payload.n * 42 }; } };',
          },
        },
      },
      topics: {
        secret: { module: '@secret/logic', initialState: 0 },
      },
    })

    const admin = await createApplicationSession({
      device: devAdmin,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys: new Map([[0, created.epoch0Key!]]),
    })
    // Blind host receives ONLY public CAS nodes (never the private @secret/logic package!)
    const blind = await createApplicationSession({
      device: devBlind,
      genesis: created.genesisBytes,
      casNodes: created.casNodes.filter(n => n.partition === 'public'),
      blindHostMode: true,
    })

    // Start an untrusted HTTP CAS mirror for testing mirror fallback
    const mirrorMap = new Map<string, Uint8Array>()
    const server = createServer((req, res) => {
      const m = /^\/cas\/sha256-([0-9a-f]{64})$/u.exec(req.url ?? '')
      if (m === null || !mirrorMap.has(m[1]!)) {
        res.writeHead(404)
        res.end()
        return
      }
      res.writeHead(200, { 'content-type': 'application/octet-stream' })
      res.end(mirrorMap.get(m[1]!)!)
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address() as { port: number }
    const mirrorUrl = `http://127.0.0.1:${addr.port}`

    try {
      await admin.submit({
        visibility: 'encrypted',
        awaitMaterialized: true,
        updates: [{ topic: 'secret', input: { n: 2 } }],
      })
      expect(admin.topic('secret')).toBe(84)

      await blind.mergeFacts(await admin.exportFacts({ includePrivateCas: false }))
      expect(blind.topic('$reducers')).toEqual(admin.topic('$reducers'))
      expect(blind.topic('$admission')).toEqual(admin.topic('$admission'))
      // Blind host has zero private package bytes!
      const secretRef = (admin.topic('$reducers') as { imports: Record<string, string> }).imports['@secret/logic']!
      expect(await blind.cas.get(parseCasRef(secretRef), 'any')).toBeNull()

      // Now test HTTP CAS mirror recovery on a public chain!
      const devM = await newMemoryDevice()
      const packed = await packReducers({
        entries: {
          '@mirror/counter': {
            source: 'export default { reduce(s: number | null, tx: { payload: { n: number } }) { return { ok: true, state: (s || 0) + tx.payload.n }; } };',
          },
        },
      })
      for (const n of packed.casNodes) mirrorMap.set(n.hash, n.bytes)
      const pubCreated = await createLogGenesis({
        creator: { publicKey: devM.identity.publicKey },
        privateLog: false,
        bundle: packed,
        topics: { counter: { module: '@mirror/counter', initialState: 0 } },
      })
      // Open WITHOUT packed.casNodes — only mirrorUrl can supply @mirror/counter!
      const mirrorOnlyNodes = pubCreated.casNodes.filter(n => !mirrorMap.has(n.hash))
      const mirroredSession = await createApplicationSession({
        device: devM,
        genesis: pubCreated.genesisBytes,
        casNodes: mirrorOnlyNodes,
        casMirrors: [mirrorUrl],
      })
      try {
        await mirroredSession.submit({
          visibility: 'public',
          awaitMaterialized: true,
          updates: [{ topic: 'counter', input: { n: 99 } }],
        })
        expect(mirroredSession.topic('counter')).toBe(99)
      } finally {
        await mirroredSession.close()
      }
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()))
      await admin.close()
      await blind.close()
    }
  })

  it('dogfoods a Registry Chronolog (SQLite+FTS5+attestations) and enforces mounted Registry approval in an App Log', async () => {
    const regDev = await newMemoryDevice()
    const appAdminDev = await newMemoryDevice()
    const appUserDev = await newMemoryDevice()
    const builder1 = await generateEd25519KeyPair()
    const builder2 = await generateEd25519KeyPair()
    const auditor = await generateEd25519KeyPair()

    // 1. Spin up a public Chronolog Registry log
    const regCreated = await createRegistryGenesis({
      creator: { publicKey: regDev.identity.publicKey },
    })
    const regSession = await createApplicationSession({
      device: regDev,
      genesis: regCreated.genesisBytes,
      casNodes: regCreated.casNodes,
    })
    const registry = new RegistryClient(regSession)

    // 2. Pack a reusable Kanban reducer package and publish it to the Registry Chronolog
    const packed = await packReducers({
      entries: {
        '@community/kanban': {
          name: '@community/kanban',
          version: '1.0.0',
          source: `
            export default {
              reduce(state: readonly string[] | null, tx: { payload: { card: string } }) {
                return { ok: true, state: [...(state || []), tx.payload.card] };
              },
            };
          `,
        },
      },
    })
    const entry = packed.entries['@community/kanban']!

    // 3. Create an App Log governed by $builders (2 builder attestations + 1 audit + mounted Registry approval!)
    const appCreated = await createLogGenesis({
      creator: { publicKey: appAdminDev.identity.publicKey },
      members: [{ publicKey: appUserDev.identity.publicKey, reader: true, writer: true, administrator: false }],
      privateLog: false,
      enableMounts: true,
      builders: {
        builders: [bytesToHex(builder1.publicKeyBytes), bytesToHex(builder2.publicKeyBytes)],
        auditors: [bytesToHex(auditor.publicKeyBytes)],
        threshold: 2,
        requireAudit: true,
        requireMountApproval: 'official-registry',
      },
    })
    const appAdmin = await createApplicationSession({
      device: appAdminDev,
      genesis: appCreated.genesisBytes,
      casNodes: appCreated.casNodes,
    })
    const appUser = await createApplicationSession({
      device: appUserDev,
      genesis: appCreated.genesisBytes,
      casNodes: appCreated.casNodes,
    })

    try {
      await registry.publish({
        name: '@community/kanban',
        version: '1.0.0',
        pkgRef: entry.pkgRef,
        drvRef: entry.drvRef!,
        runtime: entry.manifest.runtime,
        builtins: entry.manifest.builtins,
        description: 'Deterministic local-first kanban board reducer',
        casNodes: packed.casNodes,
      })

      // FTS5 search finds the package cleanly!
      const matches = await registry.search('kanban')
      expect(matches).toHaveLength(1)
      expect(matches[0]!.name).toBe('@community/kanban')

      // Record 2 independent reproducible-build attestations + 1 security audit attestation
      await registry.attestBuild({ drvRef: entry.drvRef!, outputRef: entry.pkgRef, runtime: 'quickjs-ng@0.32.0', signer: bytesToHex(builder1.publicKeyBytes), privateKey: builder1.privateKey })
      await registry.attestBuild({ drvRef: entry.drvRef!, outputRef: entry.pkgRef, runtime: 'quickjs-ng@0.32.0', signer: bytesToHex(builder2.publicKeyBytes), privateKey: builder2.privateKey })
      await registry.attestAudit({ pkgRef: entry.pkgRef, verdict: 'approved', notes: 'Audited & deterministic', signer: bytesToHex(auditor.publicKeyBytes), privateKey: auditor.privateKey })

      // Mount the Registry Chronolog snapshot into the App Log!
      await appAdmin.mountLog('official-registry', regSession, {
        trustedSigners: [regDev.identity.publicKey],
      })
      await appUser.mergeFacts(await appAdmin.exportFacts())

      // Non-admin tries installing an UNPUBLISHED package -> rejected by mount_approval_required!
      const unapproved = await packReducers({
        entries: { '@rogue/pkg': { source: 'export default { reduce() { return { ok: true, state: 1 }; } };' } },
      })
      const rejInstall = await appUser.installPackage(
        { ref: unapproved.entries['@rogue/pkg']!.pkgRef, casNodes: unapproved.casNodes },
        { alias: '@rogue/pkg', topics: { bad: {} } },
      )
      expect(rejInstall.operation.inspect().materialized?.outcome).toBe('rejected')
      expect(rejInstall.operation.inspect().materialized?.rejectionCode).toBe('mount_approval_required')

      // Non-admin installs @community/kanban via RegistryClient.installInto -> ACCEPTED via 2 build + 1 audit attestations + mounted Registry proof!
      const installed = await registry.installInto(appUser, {
        name: '@community/kanban',
        topics: { board: {} },
        minBuildAttestations: 2,
        requireAudit: true,
      })
      expect(installed.operation.inspect().materialized?.outcome).toBe('accepted')

      await appUser.submit({
        visibility: 'public',
        awaitMaterialized: true,
        updates: [{ topic: 'board', input: { card: 'Ship unified Chronolog!' } }],
      })
      expect(appUser.topic('board')).toEqual(['Ship unified Chronolog!'])
    } finally {
      await regSession.close()
      await appAdmin.close()
      await appUser.close()
    }
  })
})

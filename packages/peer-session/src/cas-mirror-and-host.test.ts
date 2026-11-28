import { createServer } from 'node:http'
import { describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/canonical'
import {
  casRef,
  ContentAddressedStore,
  MemoryBytesStore,
  putDerivationNode,
  putPackageDag,
  putTreeDag,
} from '@chronolog/records'
import { signBuildAttestation, signAuditAttestation } from '@chronolog/materializer'
import {
  createApplicationSession,
  createLogGenesis,
  dryRunReducerUpgrade,
  exportLogBlueprint,
  validateLogBlueprint,
} from './index.js'
import { openApplicationDevice } from './device.js'
import {
  createBytesStoreCasMirrorStore,
  createCasMirrorClient,
  createCasMirrorHandler,
} from './mirror.js'
import {
  collectControlReferencedCasHashes,
  replayBlindHostControl,
} from './kernel.js'
import { decodeOperationCore, decodeSignedOperation, operationIdDigest } from '@chronolog/protocol'

async function makeDevice() {
  const store = new MemoryBytesStore()
  const device = await openApplicationDevice({ store, create: true })
  return { store, device, wrapKey: device.wrapKey }
}

async function startMirrorServer(handler: (req: Request) => Promise<Response>) {
  const server = createServer((req, res) => {
    void (async () => {
      const chunks: Uint8Array[] = []
      for await (const chunk of req) chunks.push(chunk as Uint8Array)
      const body = chunks.length > 0 ? Buffer.concat(chunks) : undefined
      const host = req.headers.host ?? '127.0.0.1'
      const url = `http://${host}${req.url ?? '/'}`
      const headers = new Headers()
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === 'string') headers.set(k, v)
      }
      const webReq = new Request(url, {
        method: req.method ?? 'GET',
        headers,
        ...(body !== undefined && req.method !== 'GET' && req.method !== 'HEAD' ? { body } : {}),
      })
      const webRes = await handler(webReq)
      res.statusCode = webRes.status
      webRes.headers.forEach((value, key) => res.setHeader(key, value))
      const outBuf = new Uint8Array(await webRes.arrayBuffer())
      res.end(outBuf)
    })()
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address() as { port: number }
  return {
    baseUrl: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  }
}

describe('Reusable WinterCG CAS Mirror, Trusted Derivation Caching & Blind-Host Engine', () => {
  it('serves single nodes (304 + Range), CBOR subgraphs, chronolog-tree/v1 files, and verified attestations', async () => {
    const mirrorStore = createBytesStoreCasMirrorStore(new MemoryBytesStore())
    const handler = createCasMirrorHandler({
      store: mirrorStore,
      basePath: '/_mirror',
      allowWrites: true,
    })
    const srv = await startMirrorServer(handler)
    try {
      const client = createCasMirrorClient(`${srv.baseUrl}/_mirror`)

      // 1. Build a multi-file chronolog-pkg/v1 DAG + chronolog-tree/v1 DAG locally
      const localCas = new ContentAddressedStore({ store: new MemoryBytesStore() })
      const pkg = await putPackageDag(localCas, {
        name: 'demo/pkg',
        version: '1.0.0',
        files: {
          'index.js': 'import { greet } from "./util.js"; export const msg = greet("chronolog");',
          'util.js': 'export function greet(x) { return "hello " + x; }',
        },
        exports: { '.': 'index.js' },
      }, 'public')
      const pkgNodes = await localCas.collectSubgraph([pkg.hash], { allowedPartition: 'public' })
      expect(pkgNodes.length).toBe(3) // manifest + 2 files

      // Push entire subgraph in 1 POST /cas/batch
      const pushed = await client.pushSubgraph(pkg.hash, pkgNodes.map(n => ({ hash: n.hash, bytes: n.bytes })))
      expect(pushed).toBe(true)

      // Fetch entire subgraph in 1 GET ?subgraph=1
      const pulled = await client.fetchSubgraph(pkg.hash)
      expect(pulled.length).toBe(3)
      expect(pulled.map(n => n.hash).sort()).toEqual(pkgNodes.map(n => n.hash).sort())

      // Single node ETag / 304 + Range 206
      const headRes = await fetch(`${srv.baseUrl}/_mirror/cas/sha256-${pkg.hash}`, { method: 'HEAD' })
      expect(headRes.status).toBe(200)
      const etag = headRes.headers.get('ETag')
      expect(etag).toBe(`"${pkg.hash}"`)

      const notMod = await fetch(`${srv.baseUrl}/_mirror/cas/sha256-${pkg.hash}`, {
        headers: { 'If-None-Match': etag! },
      })
      expect(notMod.status).toBe(304)

      const rangeRes = await fetch(`${srv.baseUrl}/_mirror/cas/sha256-${pkg.hash}`, {
        headers: { Range: 'bytes=0-15' },
      })
      expect(rangeRes.status).toBe(206)
      expect((await rangeRes.arrayBuffer()).byteLength).toBe(16)

      // 2. Push a chronolog-tree/v1 site and serve files via /trees/:hash/*path with 304
      const tree = await putTreeDag(localCas, {
        'index.html': '<!doctype html><h1>Hello CAS Tree</h1>',
        'app.js': 'console.log("hi");',
      }, 'public')
      const treeNodes = await localCas.collectSubgraph([tree.hash], { allowedPartition: 'public' })
      expect(await client.pushSubgraph(tree.hash, treeNodes.map(n => ({ hash: n.hash, bytes: n.bytes })))).toBe(true)

      const htmlRes = await fetch(`${srv.baseUrl}/_mirror/trees/sha256-${tree.hash}/index.html`)
      expect(htmlRes.status).toBe(200)
      expect(htmlRes.headers.get('Content-Type')).toContain('text/html')
      expect(await htmlRes.text()).toBe('<!doctype html><h1>Hello CAS Tree</h1>')

      const html304 = await fetch(`${srv.baseUrl}/_mirror/trees/sha256-${tree.hash}/index.html`, {
        headers: { 'If-None-Match': htmlRes.headers.get('ETag')! },
      })
      expect(html304.status).toBe(304)

      // 3. Verified audit attestation PUT/GET (forged signature rejected)
      const auditor = await makeDevice()
      const audit = await signAuditAttestation(
        { pkgRef: pkg.ref, verdict: 'approved', notes: 'clean' },
        auditor.device.identity.publicKey,
        auditor.device.identity.privateKey,
      )
      expect(await client.publishAuditAttestation(audit)).toBe(true)
      const audits = await client.fetchAuditAttestations(pkg.ref)
      expect(audits).toHaveLength(1)
      expect(audits[0]!.payload.verdict).toBe('approved')

      // Forged signature must be rejected by mirror
      const forged = { ...audit, signature: '00'.repeat(64) }
      expect(await client.publishAuditAttestation(forged)).toBe(false)
    } finally {
      await srv.close()
    }
  })

  it('resolves trusted M-of-N derivation attestations from a CAS mirror without local build execution', async () => {
    const mirrorStore = createBytesStoreCasMirrorStore(new MemoryBytesStore())
    const handler = createCasMirrorHandler({ store: mirrorStore, allowWrites: true })
    const srv = await startMirrorServer(handler)
    try {
      const client = createCasMirrorClient(srv.baseUrl)
      const builderA = await makeDevice()
      const builderB = await makeDevice()
      const consumer = await makeDevice()

      // Create a deterministic output artifact + derivation node
      const buildCas = new ContentAddressedStore({ store: new MemoryBytesStore() })
      const fakeBuilderHash = await buildCas.put(utf8('export default { derive() { throw new Error("SHOULD_NOT_RUN_LOCALLY"); } }'), [], 'public')
      const srcHash = await buildCas.put(utf8('export const x = 42;'), [], 'public')
      const drv = await putDerivationNode(buildCas, {
        format: 'chronolog-drv/v1',
        profile: 'quickjs-inline',
        builder: casRef(fakeBuilderHash),
        inputs: { src: casRef(srcHash) },
        args: { mode: 'prod' },
        limits: { maxMemoryBytes: 8 * 1024 * 1024, maxFuel: 100_000 },
      }, 'public')
      const outPkg = await putPackageDag(buildCas, {
        name: 'built/widget',
        files: { 'index.js': 'export default { query() { return 42; } };' },
        exports: { '.': 'index.js' },
        derivation: drv.ref,
      }, 'public')

      // Push output subgraph + 2-of-2 builder attestations to the mirror
      const outNodes = await buildCas.collectSubgraph([outPkg.hash], { allowedPartition: 'public' })
      await client.pushSubgraph(outPkg.hash, outNodes.map(n => ({ hash: n.hash, bytes: n.bytes })))
      const attA = await signBuildAttestation(
        { drvRef: drv.ref, outputRef: outPkg.ref, runtime: 'chronolog-quickjs/v2' },
        builderA.device.identity.publicKey,
        builderA.device.identity.privateKey,
      )
      const attB = await signBuildAttestation(
        { drvRef: drv.ref, outputRef: outPkg.ref, runtime: 'chronolog-quickjs/v2' },
        builderB.device.identity.publicKey,
        builderB.device.identity.privateKey,
      )
      expect(await client.publishDerivationAttestation(attA)).toBe(true)
      expect(await client.publishDerivationAttestation(attB)).toBe(true)

      // Consumer log configures $builders with threshold=2 and casMirrors=[srv.baseUrl]
      const genesis = await createLogGenesis({
        creator: {
          publicKey: consumer.device.identity.publicKey,
          wrapKey: consumer.wrapKey.publicKey,
          subject: 'agent',
        },
        privateLog: false,
        builders: {
          builders: [builderA.device.identity.publicKey, builderB.device.identity.publicKey],
          threshold: 2,
        },
      })
      const session = await createApplicationSession({
        device: consumer.device,
        genesis: genesis.genesisBytes,
        casNodes: genesis.casNodes,
        casMirrors: [srv.baseUrl],
      })
      try {
        // Note: consumer does NOT even have the builder or derivation inputs locally —
        // it trusts the 2-of-2 Ed25519 builder attestations and pulls the verified output subgraph!
        const res = await session.evaluateDerivation(drv.ref)
        expect(res.fromCache).toBe(true)
        expect(res.outputRef).toBe(outPkg.ref)
        expect(res.attestedBy).toEqual([builderA.device.identity.publicKey, builderB.device.identity.publicKey].sort())
        expect(session.cas.hasSync(outPkg.hash, 'public')).toBe(true)
      } finally {
        await session.close()
      }
    } finally {
      await srv.close()
    }
  })

  it('runs replayBlindHostControl, dryRunReducerUpgrade, exportLogBlueprint, and native genesis admission', async () => {
    const owner = await makeDevice()
    const genesis = await createLogGenesis({
      creator: {
        publicKey: owner.device.identity.publicKey,
        wrapKey: owner.wrapKey.publicKey,
        subject: 'device',
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
      },
      privateLog: true,
      admission: {
        hostKey: 'aa'.repeat(32),
        mode: 'attested',
        accounts: ['acct-1'],
        grant: { reader: true, writer: true, administrator: true },
        invites: [],
      },
      topics: {
        db: { module: 'chronolog/sql' },
      },
      packages: {
        'app/counter': {
          name: 'app/counter',
          files: {
            'index.js': 'import { step } from "./math.js"; export default { reduce(s, tx) { return { ok: true, state: step(s || 0, tx.payload?.n || 1) }; }, query(s) { return s || 0; } };',
            'math.js': 'export function step(a, b) { return a + b; }',
          },
          exports: { '.': 'index.js' },
        },
      },
    })

    // Verify native admission + subject embedded without post-hoc re-encode!
    const initPerms = genesis.genesis.initialTopics.$admission as Record<string, unknown>
    expect((initPerms.admission as Record<string, unknown>).mode).toBe('attested')
    expect(((initPerms.members as Record<string, unknown>[])[0])?.subject).toBe('device')

    const session = await createApplicationSession({
      device: owner.device,
      genesis: genesis.genesisBytes,
      casNodes: genesis.casNodes,
      ...(genesis.epoch0Key === undefined ? {} : { epochKeys: new Map([[0, genesis.epoch0Key]]) }),
    })
    try {
      // Publish a release (automatically builds chronolog-tree/v1 treeRoot!)
      await session.publishRelease({
        entry: 'index.html',
        files: [{ path: 'index.html', bytes: utf8('<h1>App</h1>'), type: 'text/html' }],
      })
      const pub = session.topic('$publications') as { current?: { treeRoot?: string } }
      expect(pub.current?.treeRoot).toMatch(/^cas:sha256-[0-9a-f]{64}$/u)

      // Dry-run a candidate reducer upgrade before installing
      const dry = await dryRunReducerUpgrade({
        specifier: 'app/v2',
        pkg: {
          name: 'app/v2',
          files: { 'index.js': 'export default { reduce(s, tx) { return { ok: true, state: (s || 0) + (tx.payload?.d || 2) }; }, query(s) { return s || 0; } };' },
          exports: { '.': 'index.js' },
        },
        sampleInputs: [{ payload: { d: 5 } }],
      })
      expect(dry.ok).toBe(true)
      expect(dry.sampleOutcomes[0]?.ok).toBe(true)
      expect(dry.sampleQueryResult).toBe(5)

      // Export and validate portable log blueprint (includes transitive chronolog-pkg/v1 subgraph!)
      const bp = await exportLogBlueprint(session)
      const validated = validateLogBlueprint(bp)
      expect(validated.blueprint.imports['app/counter']).toMatch(/^cas:sha256-/u)
      // manifest + index.js + math.js = 3 nodes for app/counter
      expect(validated.casNodes.length).toBeGreaterThanOrEqual(3)

      // Replay through upstream replayBlindHostControl
      const facts = await session.exportPublicControlFacts()
      const kernelOps = facts.publicOps.map(raw => {
        const signed = decodeSignedOperation(raw)
        return { opId: operationIdDigest(signed.coreBytes), core: decodeOperationCore(signed.coreBytes), verified: true }
      })
      const blind = await replayBlindHostControl({
        genesis: genesis.genesis,
        publicOps: kernelOps,
        publicCasNodes: facts.casNodes.map(n => ({ hash: n.hash, bytes: n.bytes })),
      })
      expect(blind.roster.mode).toBe('attested')
      expect(blind.roster.administrators).toContain(owner.device.identity.publicKey)
      expect(blind.roster.publishers).toContain(owner.device.identity.publicKey)
      // Reachability includes transitive package files AND publication treeRoot!
      const refHashes = await collectControlReferencedCasHashes({
        genesis: genesis.genesis,
        topics: blind.topics,
        publicOps: kernelOps.map(o => o.core),
        casNodes: new Map(facts.casNodes.map(n => [n.hash, n.bytes])),
      })
      expect(refHashes.size).toBe(blind.referencedCasHashes.size)
      expect(blind.referencedCasHashes.has(pub.current!.treeRoot!.slice('cas:sha256-'.length))).toBe(true)
    } finally {
      await session.close()
    }
  })
})

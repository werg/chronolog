import { describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/canonical'
import {
  casRef,
  ContentAddressedStore,
  MemoryBytesStore,
  putTreeDag,
} from '@chronolog/records'
import { signAuditAttestation, signBuildAttestation } from '@chronolog/materializer'
import { openApplicationDevice } from './device.js'
import {
  createBytesStoreCasMirrorStore,
  createCasAdapterMirrorStore,
  createCasMirrorHandler,
  MIRROR_ATTESTATION_LIMIT,
  type CasMirrorStore,
  type MirrorBuildAttestation,
} from './mirror.js'

async function makeSigner() {
  const device = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
  return device.identity
}

async function seedTree(store: CasMirrorStore, files: Readonly<Record<string, string>>): Promise<string> {
  const local = new ContentAddressedStore({ store: new MemoryBytesStore() })
  const tree = await putTreeDag(local, files, 'public')
  for (const node of await local.collectSubgraph([tree.hash], { allowedPartition: 'public' })) {
    await store.putNode!(node.hash, node.bytes)
  }
  return tree.hash
}

const drvHash = 'a'.repeat(64)
const outHash = 'b'.repeat(64)

async function buildAttestation(runtime = 'chronolog-quickjs/v2'): Promise<MirrorBuildAttestation> {
  const signer = await makeSigner()
  return signBuildAttestation(
    { drvRef: casRef(drvHash), outputRef: casRef(outHash), runtime },
    signer.publicKey,
    signer.privateKey,
  )
}

describe('CAS mirror tree serving is inert unless allowlisted', () => {
  it('serves non-allowlisted trees as sandboxed attachments (including 304)', async () => {
    const store = createBytesStoreCasMirrorStore(new MemoryBytesStore())
    const treeHash = await seedTree(store, { 'index.html': '<script>alert(document.cookie)</script>' })
    const handler = createCasMirrorHandler({ store, allowWrites: true })

    const res = await handler(new Request(`https://mirror.test/trees/sha256-${treeHash}/index.html`))
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toBe('application/octet-stream')
    expect(res.headers.get('Content-Disposition')).toBe('attachment; filename="index.html"')
    expect(res.headers.get('Content-Security-Policy')).toContain('sandbox')
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(res.headers.get('Cache-Control')).toBe('no-store')

    const notModified = await handler(new Request(`https://mirror.test/trees/sha256-${treeHash}/index.html`, {
      headers: { 'If-None-Match': res.headers.get('ETag')! },
    }))
    expect(notModified.status).toBe(304)
    expect(notModified.headers.get('Content-Security-Policy')).toContain('sandbox')
    expect(notModified.headers.get('Content-Type')).toBe('application/octet-stream')
  })

  it('renders only trees accepted by isServableTree', async () => {
    const store = createBytesStoreCasMirrorStore(new MemoryBytesStore())
    const trusted = await seedTree(store, { 'index.html': '<h1>trusted</h1>' })
    const untrusted = await seedTree(store, { 'index.html': '<h1>guest</h1>' })
    const handler = createCasMirrorHandler({
      store,
      isServableTree: async hash => hash === trusted,
    })

    const ok = await handler(new Request(`https://mirror.test/trees/sha256-${trusted}/index.html`))
    expect(ok.headers.get('Content-Type')).toContain('text/html')
    expect(ok.headers.get('Content-Security-Policy')).toBeNull()
    expect(ok.headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(ok.headers.get('Cache-Control')).toContain('immutable')

    const guest = await handler(new Request(`https://mirror.test/trees/sha256-${untrusted}/index.html`))
    expect(guest.headers.get('Content-Type')).toBe('application/octet-stream')
    expect(guest.headers.get('Content-Security-Policy')).toContain('sandbox')
  })
})

describe('CAS mirror attestation storage', () => {
  it('keeps every attestation under concurrent writers', async () => {
    const store = createBytesStoreCasMirrorStore(new MemoryBytesStore())
    const atts = await Promise.all(Array.from({ length: 8 }, () => buildAttestation()))
    await Promise.all(atts.map(att => store.putAttestation!(drvHash, att)))
    const listed = await store.listAttestations!(drvHash)
    expect(listed.map(a => a.signer).sort()).toEqual(atts.map(a => a.signer).sort())

    // Re-publishing the same attestation is idempotent.
    await store.putAttestation!(drvHash, atts[0]!)
    expect(await store.listAttestations!(drvHash)).toHaveLength(8)
  })

  it('keeps concurrent audits from distinct signers', async () => {
    const store = createBytesStoreCasMirrorStore(new MemoryBytesStore())
    const pkgHash = 'c'.repeat(64)
    const audits = await Promise.all(Array.from({ length: 4 }, async () => {
      const signer = await makeSigner()
      return signAuditAttestation({ pkgRef: casRef(pkgHash), verdict: 'approved' }, signer.publicKey, signer.privateKey)
    }))
    await Promise.all(audits.map(a => store.putAudit!(pkgHash, a as never)))
    expect(await store.listAudits!(pkgHash)).toHaveLength(4)
  })

  it('bounds attestations per subject and maps the limit to HTTP 507', async () => {
    const store = createBytesStoreCasMirrorStore(new MemoryBytesStore(), { maxAttestationsPerSubject: 2 })
    await store.putAttestation!(drvHash, await buildAttestation())
    await store.putAttestation!(drvHash, await buildAttestation())
    await expect(store.putAttestation!(drvHash, await buildAttestation())).rejects.toThrow(MIRROR_ATTESTATION_LIMIT)
    expect(await store.listAttestations!(drvHash)).toHaveLength(2)

    const handler = createCasMirrorHandler({ store, allowWrites: true })
    const res = await handler(new Request(`https://mirror.test/derivations/sha256-${drvHash}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(await buildAttestation()),
    }))
    expect(res.status).toBe(507)
  })
})

describe('createCasAdapterMirrorStore', () => {
  it('exposes only the public CAS partition', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const privateHash = await cas.put(utf8('secret'), [], 'private')
    const publicHash = await cas.put(utf8('hello'), [], 'public')
    // @ts-expect-error the partition option no longer exists
    const mirror = createCasAdapterMirrorStore(cas, { partition: 'private' })
    expect(await mirror.getNode(privateHash)).toBeNull()
    expect(await mirror.hasNode!(privateHash)).toBe(false)
    expect(await mirror.getNode(publicHash)).not.toBeNull()

    const handler = createCasMirrorHandler({ store: mirror })
    const res = await handler(new Request(`https://mirror.test/cas/sha256-${privateHash}`))
    expect(res.status).toBe(404)
  })
})

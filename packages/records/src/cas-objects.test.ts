import { describe, expect, it } from 'vitest'
import {
  casRef,
  computeBlobDagHash,
  ContentAddressedStore,
  decodeDerivationNode,
  decodeEncBlobManifest,
  decodePackageNode,
  decodeTreeNode,
  encodeEncBlobManifest,
  MemoryBytesStore,
  parseCasRef,
  putBlobDag,
  putDerivationNode,
  putPackageDag,
  putTreeDag,
  readBlobDag,
  readBlobDagSync,
  resolvePackageRelativePath,
  statBlobDag,
  streamBlobDag,
} from './index.js'

describe('Unified CAS Merkle-DAG objects', () => {
  it('stores, stats, reads, and streams small and multi-chunk chronolog-blob/v1 DAGs', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })

    const small = new TextEncoder().encode('hello chronolog cas')
    const smallStored = await putBlobDag(cas, small, 'public')
    expect(smallStored.hash).toBe(computeBlobDagHash(small))
    expect(await statBlobDag(cas, smallStored.hash, 'public')).toEqual({
      hash: smallStored.hash,
      bytes: small.byteLength,
      chunked: false,
    })
    expect(await readBlobDag(cas, smallStored.hash, 'public')).toEqual(small)

    // 200 KiB (> 3 chunks of 64 KiB)
    const large = new Uint8Array(200_000).map((_, i) => (i * 17 + 3) & 0xff)
    const largeStored = await putBlobDag(cas, large, 'public')
    expect(largeStored.hash).toBe(computeBlobDagHash(large))
    expect(await statBlobDag(cas, largeStored.hash, 'public')).toEqual({
      hash: largeStored.hash,
      bytes: large.byteLength,
      chunked: true,
    })
    expect(await readBlobDag(cas, largeStored.hash, 'public')).toEqual(large)
    expect(readBlobDagSync(cas, largeStored.hash, 'public', h => { throw new Error(`missing:${h}`) })).toEqual(large)

    const streamed: Uint8Array[] = []
    for await (const chunk of streamBlobDag(cas, largeStored.hash, 'public')) streamed.push(chunk)
    expect(streamed.length).toBe(4)
    expect(streamed.reduce((a, b) => a + b.byteLength, 0)).toBe(large.byteLength)
  })

  it('encodes chronolog-pkg/v1 with transitive links for files+deps while excluding derivation back-links', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const dep = await putPackageDag(cas, {
      name: 'helper-lib',
      version: '1.0.0',
      files: { 'index.js': 'export const double = x => x * 2;' },
      builtins: [],
    })
    const srcTree = await putTreeDag(cas, { 'src/index.ts': 'export const x: number = 1;' })
    const drv = await putDerivationNode(cas, {
      format: 'chronolog-drv/v1',
      profile: 'wasi-cas-v1',
      builder: dep.ref,
      inputs: { src: srcTree.ref },
      args: { mode: 'prod' },
      limits: { maxMemoryBytes: 64 * 1024 * 1024, maxFuel: 100_000 },
    })

    const appPkg = await putPackageDag(cas, {
      name: '@app/demo',
      version: '2.0.0',
      files: {
        'index.js': 'import { double } from "helper-lib"; export default { double };',
        'sub/util.js': 'export const ok = true;',
      },
      exports: { '.': 'index.js', './util': 'sub/util.js' },
      dependencies: { 'helper-lib': dep.ref },
      builtins: ['chronolog:crypto'],
      derivation: drv.ref,
    })

    const rawNode = await cas.get(appPkg.hash, 'public')
    expect(rawNode).not.toBeNull()
    const decoded = decodePackageNode(rawNode!.bytes)
    expect(decoded.name).toBe('@app/demo')
    expect(decoded.derivation).toBe(drv.ref)
    expect(decoded.builtins).toEqual(['chronolog:crypto'])

    // Reachable executable subgraph includes files + dependency pkg + dependency files, NOT derivation/source tree!
    const reachable = await cas.reachable([appPkg.hash])
    expect(reachable.has(appPkg.hash)).toBe(true)
    expect(reachable.has(dep.hash)).toBe(true)
    expect(reachable.has(parseCasRef(dep.manifest.files['index.js']!))).toBe(true)
    expect(reachable.has(drv.hash)).toBe(false)
    expect(reachable.has(srcTree.hash)).toBe(false)

    // collectSubgraph collects the full executable package DAG in one call
    const sub = await cas.collectSubgraph([appPkg.hash], { allowedPartition: 'public' })
    expect(sub.map(n => n.hash).sort()).toEqual([...reachable].sort())

    // Derivation and tree roundtrip cleanly
    const drvNode = await cas.get(drv.hash, 'public')
    expect(decodeDerivationNode(drvNode!.bytes).inputs.src).toBe(srcTree.ref)
    const treeNode = await cas.get(srcTree.hash, 'public')
    expect(Object.keys(decodeTreeNode(treeNode!.bytes).entries)).toEqual(['src/index.ts'])

    // Relative path resolution guards against path escape
    expect(resolvePackageRelativePath('sub/util.js', '../index.js')).toBe('index.js')
    expect(() => resolvePackageRelativePath('index.js', '../escape.js')).toThrow('PACKAGE_PATH_ESCAPE')
  })

  it('encodes chronolog-enc-blob/v1 manifests and honors pin/unpin + deleteNodes during GC', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const c1 = await cas.put(new Uint8Array([1, 2, 3]), [], 'public')
    const c2 = await cas.put(new Uint8Array([4, 5, 6]), [], 'public')
    const enc = encodeEncBlobManifest({
      format: 'chronolog-enc-blob/v1',
      applicationId: 'aa'.repeat(32),
      epoch: 0,
      bytes: 6,
      mediaType: 'application/octet-stream',
      chunks: [
        { hash: c1, bytes: 3, plainBytes: 3 },
        { hash: c2, bytes: 3, plainBytes: 3 },
      ],
    })
    const root = await cas.put(enc.bytes, enc.links, 'public')
    const decoded = decodeEncBlobManifest((await cas.get(root, 'public'))!.bytes)
    expect(decoded.chunks.map(c => c.hash)).toEqual([c1, c2])

    // Pin root -> GC with empty roots still keeps root + both chunks!
    cas.pin(root)
    const gc1 = await cas.collectGarbage([])
    expect(gc1.kept).toBe(3)
    expect(gc1.deleted).toBe(0)
    expect(casRef(root)).toBe(`cas:sha256-${root}`)

    // Unpin -> deleteNodes removes them cleanly
    cas.unpin(root)
    const deleted = await cas.deleteNodes([root, c1, c2], 'public')
    expect(deleted).toBe(3)
    expect(await cas.get(root, 'public')).toBeNull()
  })
})

import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/canonical'
import { createApplicationSession, createLogGenesis, openApplicationDevice } from '@chronolog/peer-session'
import { casRef, ContentAddressedStore, MemoryBytesStore, putDerivationNode, putPackageDag } from '@chronolog/records'
import {
  createDeterministicTar,
  formatLockfile,
  INLINE_TS_BUILDER_SOURCE,
  ingestTarballToCas,
  lintDeterminism,
  packNpmTarball,
  packReducers,
  parseLockfile,
} from './index.js'

describe('@chronolog/pack — determinism linter, npm tarball ingester, lockfile & TypeScript packer', () => {
  it('lints nondeterministic APIs with accurate locations while ignoring comments and strings', () => {
    const clean = `
      // Date.now() and Math.random() inside comments are fine
      const msg = "fetch('https://example.com') inside string is fine";
      export default {
        reduce(state, tx) { return { ok: true, state: { at: tx.authorTimestampMs, msg } }; }
      };
    `
    expect(lintDeterminism(clean, 'clean.js')).toEqual([])

    const dirty = [
      'import fs from "node:fs";',
      'export default {',
      '  async reduce(state) {',
      '    const t = Date.now();',
      '    const r = Math.random();',
      '    return { ok: true, state: { t, r, fs: Boolean(fs) } };',
      '  }',
      '};',
    ].join('\n')
    const diags = lintDeterminism(dirty, 'dirty.ts')
    expect(diags.map(d => d.code)).toEqual([
      'forbidden:host-io',
      'forbidden:async-reducer',
      'nondeterministic:date',
      'nondeterministic:random',
    ])
    expect(diags[2]!.line).toBe(4)
  })

  it('ingests npm tarballs canonically (identical hash regardless of packing metadata) and enforces integrity', async () => {
    const files = {
      'package.json': JSON.stringify({ name: 'mini-math', version: '1.2.3', main: 'index.js' }),
      'index.js': 'exports.scale = function(n) { return n * 7; };',
    }
    const tar = createDeterministicTar(files)
    const gz = new Uint8Array(gzipSync(tar))
    const integrity = `sha512-${createHash('sha512').update(gz).digest('base64')}`

    const cas1 = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const cas2 = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const tree1 = await ingestTarballToCas(cas1, tar)
    const tree2 = await ingestTarballToCas(cas2, gz, { integrity })
    expect(tree1.ref).toBe(tree2.ref)

    await expect(ingestTarballToCas(cas2, gz, { integrity: 'sha512-WRONG' })).rejects.toThrow('TARBALL_INTEGRITY_MISMATCH')

    const packed = await packNpmTarball({ tarball: gz, integrity })
    expect(packed.manifest.name).toBe('mini-math')
    expect(packed.manifest.version).toBe('1.2.3')
    expect(packed.drvRef).toBeDefined()
  })

  it('packs real TypeScript reducers importing a CommonJS npm package (with dead node:fs branch) and runs them in a live ApplicationSession', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'chronolog-pack-test-'))
    try {
      // Simulate a real npm ESM package in node_modules with a dead dev-only Date.now() branch (tree-shaken away!)
      await mkdir(join(dir, 'node_modules/mini-zod'), { recursive: true })
      await writeFile(
        join(dir, 'node_modules/mini-zod/package.json'),
        JSON.stringify({ name: 'mini-zod', version: '1.0.0', type: 'module', module: 'index.js', sideEffects: false }),
      )
      await writeFile(
        join(dir, 'node_modules/mini-zod/index.js'),
        `
          export function nonEmptyString(v) {
            if (process.env.NODE_ENV !== 'production') {
              // Dead dev-only timing check stripped by deterministic production bundling!
              void Date.now();
            }
            if (typeof v !== 'string' || v.trim().length === 0) throw new Error('EMPTY_STRING');
            return v.trim();
          }
          export function unusedHelper() {
            return Math.random();
          }
        `,
      )

      await mkdir(join(dir, 'reducers'), { recursive: true })
      await writeFile(join(dir, 'reducers/slug.ts'), `export function toSlug(s: string): string { return s.toLowerCase().replace(/[^a-z0-9]+/g, '-'); }\n`)
      await writeFile(
        join(dir, 'reducers/tasks.ts'),
        `
          import { nonEmptyString } from 'mini-zod';
          import { toSlug } from './slug.js';
          import { sha256 } from 'chronolog:crypto';

          interface Task { readonly id: string; readonly slug: string; readonly title: string; }

          export default {
            reduce(state: readonly Task[] | null, tx: { payload: { title: string }; opId: string }) {
              const title = nonEmptyString(tx.payload.title);
              const list = Array.isArray(state) ? state : [];
              const next: Task = { id: sha256(tx.opId).slice(0, 12), slug: toSlug(title), title };
              return { ok: true, state: [...list, next] };
            },
          };
        `,
      )

      const packed = await packReducers({
        cwd: dir,
        entries: {
          '@app/tasks': './reducers/tasks.ts',
        },
      })

      expect(packed.entries['@app/tasks']!.manifest.builtins).toEqual(['chronolog:crypto'])
      expect(packed.entries['@app/tasks']!.drvRef).toBeDefined()

      // Lockfile roundtrips cleanly
      const lockText = formatLockfile(packed.lockfile)
      expect(parseLockfile(lockText)).toEqual(packed.lockfile)

      // Execute packed TypeScript + npm reducer directly inside a real ApplicationSession!
      const dev = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
      const created = await createLogGenesis({
        creator: { publicKey: dev.identity.publicKey, wrapKey: dev.wrapKey.publicKey },
        bundle: packed,
        topics: { tasks: { module: '@app/tasks', initialState: [] } },
      })
      const session = await createApplicationSession({
        device: dev,
        genesis: created.genesisBytes,
        casNodes: created.casNodes,
        epochKeys: new Map([[0, created.epoch0Key!]]),
      })
      try {
        await session.submit({
          visibility: 'encrypted',
          awaitMaterialized: true,
          updates: [{ topic: 'tasks', input: { title: '  Ship Chronolog v3!  ' } }],
        })
        const tasks = session.topic('tasks') as readonly { slug: string; title: string }[]
        expect(tasks).toHaveLength(1)
        expect(tasks[0]!.title).toBe('Ship Chronolog v3!')
        expect(tasks[0]!.slug).toBe('ship-chronolog-v3-')

        // Also test in-sandbox zero-authority TypeScript stripping derivation!
        const inlineBuilder = await putPackageDag(session.cas, {
          name: 'inline-ts',
          files: { 'index.js': INLINE_TS_BUILDER_SOURCE },
          builtins: ['chronolog:cas'],
        })
        const rawTsHash = await session.cas.put(utf8('export function add(a: number, b: number): number { return a + b; }'), [], 'public')
        const drv = await putDerivationNode(session.cas, {
          format: 'chronolog-drv/v1',
          profile: 'quickjs-inline',
          builder: inlineBuilder.ref,
          inputs: { src: casRef(rawTsHash) },
          args: {},
          limits: { maxMemoryBytes: 32 * 1024 * 1024, maxFuel: 100_000 },
        })
        const derived = await session.evaluateDerivation(drv.ref)
        expect(derived.fromCache).toBe(false)
        const derivedBytes = await session.readCasPayload(derived.outputHash, 'public')
        expect(new TextDecoder().decode(derivedBytes!.payload)).toContain('export function add(a, b) { return a + b; }')
      } finally {
        await session.close()
      }
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

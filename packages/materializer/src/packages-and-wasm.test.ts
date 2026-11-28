import { describe, expect, it } from 'vitest'
import { bytesToHex, utf8 } from '@chronolog/canonical'
import {
  DEFAULT_GENESIS_LIMITS,
  DEFAULT_RUNTIME_MANIFEST,
  encodeLogGenesis,
  genesisLogId,
  operationIdDigest,
  signOperationCore,
  type JsonValue,
  type LogGenesis,
  type OperationCore,
} from '@chronolog/protocol'

async function generateEd25519KeyPair(): Promise<{ readonly privateKey: CryptoKey; readonly publicKey: CryptoKey; readonly publicKeyBytes: Uint8Array }> {
  const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, publicKeyBytes }
}
import {
  casRef,
  ContentAddressedStore,
  MemoryBytesStore,
  putDerivationNode,
  putPackageDag,
} from '@chronolog/records'
import {
  createBytesStoreDerivationMemo,
  evaluateDerivation,
  QuickJsSandbox,
  seedStandardModules,
  signAuditAttestation,
  signBuildAttestation,
  TopicKernel,
  verifyDerivationOutput,
} from './index.js'

/** Minimal hand-assembled valid WebAssembly module exporting `add(i32, i32) -> i32`. */
const WASM_ADD_BYTES = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, // \0asm
  0x01, 0x00, 0x00, 0x00, // version 1
  // Type section (1): 1 type: (i32, i32) -> i32
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
  // Function section (3): 1 func of type 0
  0x03, 0x02, 0x01, 0x00,
  // Export section (7): export "add" -> func 0
  0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
  // Code section (10): local.get 0, local.get 1, i32.add, end
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
])

/**
 * Valid standalone pure-WASM reducer (chronolog-wasm/v1 ABI):
 * Exports: memory (1 page, max 1), alloc(len)->i32, reduce(ptr,len)->i64 (packed outPtr<<32 | outLen),
 * returning canonical JSON `{"ok":true,"state":{"wasm":true}}` stored in linear memory at offset 16.
 */
function buildPureWasmReducerBytes(jsonResponse: string): Uint8Array {
  const respBytes = utf8(jsonResponse)
  const outPtr = 16
  const outLen = respBytes.byteLength
  // Encode unsigned LEB128
  const uleb = (n: number): number[] => {
    const out: number[] = []
    let v = n >>> 0
    do {
      let b = v & 0x7f
      v >>>= 7
      if (v !== 0) b |= 0x80
      out.push(b)
    } while (v !== 0)
    return out
  }
  // Signed LEB128 for i64 constant
  const sleb64 = (n: bigint): number[] => {
    const out: number[] = []
    let v = n
    let more = true
    while (more) {
      let b = Number(v & 0x7fn)
      v >>= 7n
      if ((v === 0n && (b & 0x40) === 0) || (v === -1n && (b & 0x40) !== 0)) {
        more = false
      } else {
        b |= 0x80
      }
      out.push(b)
    }
    return out
  }
  const sec = (id: number, body: number[]): number[] => [id, ...uleb(body.length), ...body]
  const str = (s: string): number[] => {
    const b = [...utf8(s)]
    return [...uleb(b.length), ...b]
  }

  // Types: 0: (i32)->i32 [alloc], 1: (i32,i32)->i64 [reduce]
  const typeSec = sec(1, [
    0x02,
    0x60, 0x01, 0x7f, 0x01, 0x7f,
    0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e,
  ])
  const funcSec = sec(3, [0x02, 0x00, 0x01])
  const memSec = sec(5, [0x01, 0x01, 0x01, 0x01]) // 1 page, declared max 1 page (required)
  const expSec = sec(7, [
    0x03,
    ...str('memory'), 0x02, 0x00,
    ...str('alloc'), 0x00, 0x00,
    ...str('reduce'), 0x00, 0x01,
  ])
  // alloc: returns 1024
  const allocBody = [0x00, 0x41, ...uleb(1024), 0x0b]
  // reduce: returns i64.const ((outPtr << 32) | outLen)
  const packed = (BigInt(outPtr) << 32n) | BigInt(outLen)
  const reduceBody = [0x00, 0x42, ...sleb64(packed), 0x0b]
  const codeSec = sec(10, [
    0x02,
    ...uleb(allocBody.length), ...allocBody,
    ...uleb(reduceBody.length), ...reduceBody,
  ])
  // Data segment placing respBytes at offset 16
  const dataSeg = [0x00, 0x41, ...uleb(outPtr), 0x0b, ...uleb(respBytes.length), ...respBytes]
  const dataSec = sec(11, [0x01, ...dataSeg])

  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...typeSec, ...funcSec, ...memSec, ...expSec, ...codeSec, ...dataSec,
  ])
}

async function makeOp(
  logId: Uint8Array,
  author: CryptoKeyPair,
  authorPub: Uint8Array,
  operationId: string,
  authorTimestampMs: bigint,
  updates: OperationCore['updates'],
  visibility: 'public' | 'encrypted' = 'public',
) {
  const core: OperationCore = {
    version: 1,
    logId,
    author: authorPub,
    operationId,
    authorTimestampMs,
    nonce: new Uint8Array(16).fill(Number(authorTimestampMs % 250n) + 1),
    visibility,
    updates,
  }
  const signed = await signOperationCore(core, author.privateKey)
  return { opId: operationIdDigest(signed.coreBytes), core }
}

describe('Scoped chronolog-pkg/v1, capability attenuation, fuel, WASM, derivations & historical GC', () => {
  it('resolves multi-file relative imports, isolates diamond dependencies, and enforces per-package capability attenuation', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const stdImports = await seedStandardModules(cas)

    // Diamond dependencies: two versions of "mathlib"
    const mathV1 = await putPackageDag(cas, {
      name: 'mathlib',
      version: '1.0.0',
      files: { 'index.js': 'export const factor = 10;' },
      builtins: [],
    })
    const mathV2 = await putPackageDag(cas, {
      name: 'mathlib',
      version: '2.0.0',
      files: { 'index.js': 'export const factor = 100;' },
      builtins: [],
    })

    // Package A uses mathlib v1 + relative ./sub/helper.js + chronolog:crypto
    const pkgA = await putPackageDag(cas, {
      name: 'pkg-a',
      version: '1.0.0',
      files: {
        'index.js': `
          import { factor } from 'mathlib';
          import { tag } from './sub/helper.js';
          import { sha256 } from 'chronolog:crypto';
          export const computeA = (n) => ({ val: n * factor, tag: tag(), hash: sha256('a').slice(0, 8) });
        `,
        'sub/helper.js': `export const tag = () => 'from-a';`,
      },
      exports: { '.': 'index.js' },
      dependencies: { mathlib: mathV1.ref },
      builtins: ['chronolog:crypto'],
    })

    // Package B uses mathlib v2 (same bare specifier, different version — zero collision!)
    const pkgB = await putPackageDag(cas, {
      name: 'pkg-b',
      version: '1.0.0',
      files: {
        'index.js': `
          import { factor } from 'mathlib';
          export const computeB = (n) => n * factor;
        `,
      },
      dependencies: { mathlib: mathV2.ref },
      builtins: [],
    })

    // Root app reducer imports BOTH pkgA and pkgB (plus direct cas:sha256-... import!)
    const directLeafHash = await cas.put(utf8('export const bonus = 7;'), [], 'public')
    const appPkg = await putPackageDag(cas, {
      name: 'app',
      version: '1.0.0',
      files: {
        'index.js': `
          import { computeA } from 'pkg-a';
          import { computeB } from 'pkg-b';
          import { bonus } from '${casRef(directLeafHash)}';
          export default {
            reduce(state, tx) {
              const a = computeA(tx.payload.n);
              const b = computeB(tx.payload.n);
              return { ok: true, state: { a, b, total: a.val + b + bonus } };
            },
          };
        `,
      },
      dependencies: { 'pkg-a': pkgA.ref, 'pkg-b': pkgB.ref },
      builtins: [],
    })

    // Malicious package claiming builtins: [] but trying to import chronolog:crypto
    const roguePkg = await putPackageDag(cas, {
      name: 'rogue',
      version: '1.0.0',
      files: {
        'index.js': `
          import { sha256 } from 'chronolog:crypto';
          export default { reduce() { return { ok: true, state: sha256('x') }; } };
        `,
      },
      builtins: [], // Capability NOT declared!
    })

    const kp = await generateEd25519KeyPair()
    const genesis: LogGenesis = {
      version: 1,
      privateLog: false,
      limits: DEFAULT_GENESIS_LIMITS,
      salt: new Uint8Array(16).fill(1),
      initialTopics: {
        $reducers: {
          runtime: DEFAULT_RUNTIME_MANIFEST as unknown as JsonValue,
          imports: { ...stdImports, '@app/main': appPkg.ref, '@app/rogue': roguePkg.ref },
          topics: {
            app: { module: '@app/main' },
            rogue: { module: '@app/rogue' },
          },
        },
      },
    }
    const logId = genesisLogId(encodeLogGenesis(genesis))
    const kernel = new TopicKernel({ genesis, cas })

    const opOk = await makeOp(logId, kp, kp.publicKeyBytes, 'op-1', 100n, [{ topic: 'app', input: { n: 3 } }])
    const opRogue = await makeOp(logId, kp, kp.publicKeyBytes, 'op-2', 200n, [{ topic: 'rogue', input: {} }])
    const res = await kernel.materialize([opOk, opRogue])

    expect(res.outcomes[0]!.outcome).toBe('accepted')
    expect(kernel.topic('app')).toEqual({
      a: { val: 30, tag: 'from-a', hash: 'ca978112' },
      b: 300,
      total: 337,
    })

    // Rogue package is deterministically denied chronolog:crypto even though globally enabled!
    expect(res.outcomes[1]!.outcome).toBe('rejected')
    expect(res.outcomes[1]!.rejectionCode).toBe('vm:module_load_error')
    expect(res.outcomes[1]!.rejectionDetail).toContain('BUILTIN_CAPABILITY_DENIED')
    kernel.sandbox.dispose()
  })

  it('enforces deterministic fuel metering (vm:fuel_exhausted) and preserves historical $reducers across GC', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const stdImports = await seedStandardModules(cas)
    const kp = await generateEd25519KeyPair()
    const pubHex = bytesToHex(kp.publicKeyBytes)

    const v1 = await putPackageDag(cas, { files: { 'index.js': 'export default { reduce(s, tx) { return { ok: true, state: (s || 0) + tx.payload.n }; } };' } })
    const v2 = await putPackageDag(cas, { files: { 'index.js': 'export default { reduce(s, tx) { return { ok: true, state: (s || 0) + tx.payload.n * 10 }; } };' } })
    const v3 = await putPackageDag(cas, { files: { 'index.js': 'export default { reduce(s, tx) { return { ok: true, state: (s || 0) + tx.payload.n * 100 }; } };' } })
    const spin = await putPackageDag(cas, { files: { 'index.js': 'export default { reduce() { let x = 0; while (true) { x++; } } };' } })

    const genesis: LogGenesis = {
      version: 1,
      privateLog: false,
      limits: { ...DEFAULT_GENESIS_LIMITS, maxFuel: 40 },
      salt: new Uint8Array(16).fill(2),
      initialTopics: {
        $admission: { members: [{ publicKey: pubHex, reader: true, writer: true, administrator: true, publisher: true }], admission: null },
        $reducers: {
          runtime: DEFAULT_RUNTIME_MANIFEST as unknown as JsonValue,
          imports: { ...stdImports, '@app/calc': v1.ref, '@app/spin': spin.ref },
          topics: {
            $admission: { module: 'chronolog/admission', export: 'attestedAdmission' },
            $reducers: { module: 'chronolog/admission', export: 'adminOnlyReducers' },
            calc: { module: '@app/calc' },
            spin: { module: '@app/spin' },
          },
        },
      },
    }
    const logId = genesisLogId(encodeLogGenesis(genesis))
    const kernel = new TopicKernel({ genesis, cas, snapshotInterval: 16 })

    // 1. Infinite loop deterministically hits vm:fuel_exhausted!
    const spinOp = await makeOp(logId, kp, kp.publicKeyBytes, 'spin-1', 50n, [{ topic: 'spin', input: {} }])
    // 2. Upgrade v1 -> v2 -> v3 within 4 ops (none of which hit snapshot interval 16!)
    const opV1 = await makeOp(logId, kp, kp.publicKeyBytes, 'calc-1', 100n, [{ topic: 'calc', input: { n: 1 } }])
    const upV2 = await makeOp(logId, kp, kp.publicKeyBytes, 'up-2', 200n, [{ topic: '$reducers', input: { imports: { '@app/calc': v2.ref } } }])
    const opV2 = await makeOp(logId, kp, kp.publicKeyBytes, 'calc-2', 300n, [{ topic: 'calc', input: { n: 2 } }])
    const upV3 = await makeOp(logId, kp, kp.publicKeyBytes, 'up-3', 400n, [{ topic: '$reducers', input: { imports: { '@app/calc': v3.ref } } }])
    const opV3 = await makeOp(logId, kp, kp.publicKeyBytes, 'calc-3', 500n, [{ topic: 'calc', input: { n: 3 } }])

    const res = await kernel.materialize([spinOp, opV1, upV2, opV2, upV3, opV3])
    expect(res.outcomes[0]!.outcome).toBe('rejected')
    expect(res.outcomes[0]!.rejectionCode).toBe('vm:fuel_exhausted')
    expect(kernel.topic('calc')).toBe(1 + 20 + 300)

    // Run GC! Intermediate v2 package MUST stay alive because #historicalReducerRoots pins it!
    await cas.collectGarbage(kernel.gcRoots())
    expect(await cas.get(v2.hash, 'public')).not.toBeNull()

    // Time-travel & late-arriving op during v2 window MUST succeed cleanly after GC!
    const atV2 = await kernel.materializeAt({ atTimestampMs: 300n })
    expect(atV2.topics.calc).toBe(21)

    const lateOp = await makeOp(logId, kp, kp.publicKeyBytes, 'calc-late', 250n, [{ topic: 'calc', input: { n: 5 } }])
    await kernel.materialize([spinOp, opV1, upV2, opV2, upV3, opV3, lateOp])
    expect(kernel.topic('calc')).toBe(1 + 50 + 20 + 300)
    kernel.sandbox.dispose()
  })

  it('executes both chronolog:wasm libraries from JS and standalone pure-WASM topic reducers (cached once per hash)', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const stdImports = await seedStandardModules(cas)
    const kp = await generateEd25519KeyPair()

    const addWasmHash = await cas.put(WASM_ADD_BYTES, [], 'public')
    const hybridPkg = await putPackageDag(cas, {
      name: 'hybrid-wasm',
      runtime: 'hybrid',
      files: {
        'index.js': `
          import { invoke } from 'chronolog:wasm';
          export default {
            reduce(state, tx) {
              const next = invoke('${casRef(addWasmHash)}', 'add', [state || 0, tx.payload.delta]);
              return { ok: true, state: next };
            },
          };
        `,
      },
      builtins: ['chronolog:wasm'],
    })

    const pureWasmBytes = buildPureWasmReducerBytes('{"ok":true,"state":{"fromWasm":42}}')
    const pureWasmPkg = await putPackageDag(cas, {
      name: 'pure-wasm-topic',
      runtime: 'wasm-pure',
      files: { 'reducer.wasm': pureWasmBytes },
      wasm: { entry: 'reducer.wasm', abi: 'chronolog-wasm/v1' },
      builtins: [],
    })

    const genesis: LogGenesis = {
      version: 1,
      privateLog: false,
      limits: DEFAULT_GENESIS_LIMITS,
      salt: new Uint8Array(16).fill(3),
      initialTopics: {
        $reducers: {
          runtime: DEFAULT_RUNTIME_MANIFEST as unknown as JsonValue,
          imports: { ...stdImports, '@app/hybrid': hybridPkg.ref, '@app/purewasm': pureWasmPkg.ref },
          topics: {
            hybrid: { module: '@app/hybrid' },
            purewasm: { module: '@app/purewasm' },
          },
        },
      },
    }
    const logId = genesisLogId(encodeLogGenesis(genesis))
    const kernel = new TopicKernel({ genesis, cas })

    const ops = [
      await makeOp(logId, kp, kp.publicKeyBytes, 'h-1', 100n, [{ topic: 'hybrid', input: { delta: 19 } }]),
      await makeOp(logId, kp, kp.publicKeyBytes, 'h-2', 200n, [{ topic: 'hybrid', input: { delta: 23 } }]),
      await makeOp(logId, kp, kp.publicKeyBytes, 'w-1', 300n, [{ topic: 'purewasm', input: {} }]),
    ]
    const res = await kernel.materialize(ops)
    expect(res.outcomes.every(o => o.outcome === 'accepted')).toBe(true)
    expect(kernel.topic('hybrid')).toBe(42)
    expect(kernel.topic('purewasm')).toEqual({ fromWasm: 42 })
    // Both WASM modules compiled once and cached by hash!
    expect(kernel.sandbox.wasmSandbox.cachedModuleCount).toBe(2)
    kernel.sandbox.dispose()
  })

  it('evaluates quickjs-inline derivations deterministically with memoization and verifies M-of-N builder attestations', async () => {
    const store = new MemoryBytesStore()
    const cas = new ContentAddressedStore({ store })
    const sandbox = new QuickJsSandbox()

    // Pure in-sandbox derivation builder: wraps an input expression into a reducer module
    const builderPkg = await putPackageDag(cas, {
      name: 'expr-builder',
      files: {
        'index.js': `
          import { get, put } from 'chronolog:cas';
          export default {
            derive(payload) {
              const raw = JSON.parse(get(payload.inputs.expr));
              const hex = raw.bytesHex;
              let expr = '';
              for (let i = 0; i < hex.length; i += 2) expr += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
              const outCode = 'export default { reduce(s, tx) { return { ok: true, state: (' + expr + ') }; } };';
              const h = put(outCode, []);
              return { output: 'cas:sha256-' + h };
            },
          };
        `,
      },
      builtins: ['chronolog:cas'],
    })
    const exprHash = await cas.put(utf8('(s || 0) + tx.payload.v * 2'), [], 'public')
    const drv = await putDerivationNode(cas, {
      format: 'chronolog-drv/v1',
      profile: 'quickjs-inline',
      builder: builderPkg.ref,
      inputs: { expr: casRef(exprHash) },
      args: {},
      limits: { maxMemoryBytes: 32 * 1024 * 1024, maxFuel: 50_000 },
    })

    const memo = createBytesStoreDerivationMemo(store)
    const first = await evaluateDerivation({ drvRefOrHash: drv.ref, cas, sandbox, memo })
    expect(first.fromCache).toBe(false)
    const second = await evaluateDerivation({ drvRefOrHash: drv.ref, cas, sandbox, memo })
    expect(second.fromCache).toBe(true)
    expect(second.outputRef).toBe(first.outputRef)

    const verified = await verifyDerivationOutput({
      drvRefOrHash: drv.ref,
      expectedOutputRef: first.outputRef,
      cas,
      sandbox,
    })
    expect(verified.valid).toBe(true)

    // Test M-of-N attestedReducers governance with 2 builders + 1 auditor (non-admin submits upgrade!)
    const admin = await generateEd25519KeyPair()
    const nonAdmin = await generateEd25519KeyPair()
    const b1 = await generateEd25519KeyPair()
    const b2 = await generateEd25519KeyPair()
    const auditor = await generateEd25519KeyPair()

    const stdImports = await seedStandardModules(cas)
    const genesis: LogGenesis = {
      version: 1,
      privateLog: false,
      limits: DEFAULT_GENESIS_LIMITS,
      salt: new Uint8Array(16).fill(4),
      initialTopics: {
        $admission: {
          members: [
            { publicKey: bytesToHex(admin.publicKeyBytes), reader: true, writer: true, administrator: true, publisher: true },
            { publicKey: bytesToHex(nonAdmin.publicKeyBytes), reader: true, writer: true, administrator: false, publisher: false },
          ],
          admission: null,
        },
        $builders: {
          builders: [bytesToHex(b1.publicKeyBytes), bytesToHex(b2.publicKeyBytes)].sort(),
          auditors: [bytesToHex(auditor.publicKeyBytes)],
          threshold: 2,
          requireAudit: true,
          requireMountApproval: null,
        },
        $reducers: {
          runtime: DEFAULT_RUNTIME_MANIFEST as unknown as JsonValue,
          imports: { ...stdImports },
          topics: {
            $reducers: { module: 'chronolog/builders', export: 'attestedReducers' },
            $builders: { module: 'chronolog/builders', export: 'attestedBuilders' },
          },
        },
      },
    }
    const logId = genesisLogId(encodeLogGenesis(genesis))
    const kernel = new TopicKernel({ genesis, cas })

    const att1 = await signBuildAttestation({ drvRef: drv.ref, outputRef: first.outputRef, runtime: 'quickjs-ng@0.32.0' }, bytesToHex(b1.publicKeyBytes), b1.privateKey)
    const att2 = await signBuildAttestation({ drvRef: drv.ref, outputRef: first.outputRef, runtime: 'quickjs-ng@0.32.0' }, bytesToHex(b2.publicKeyBytes), b2.privateKey)
    const aud = await signAuditAttestation({ pkgRef: first.outputRef, verdict: 'approved', notes: 'LGTM' }, bytesToHex(auditor.publicKeyBytes), auditor.privateKey)

    // Only 1 attestation -> rejected!
    const failOp = await makeOp(logId, nonAdmin, nonAdmin.publicKeyBytes, 'up-fail', 100n, [{
      topic: '$reducers',
      input: {
        imports: { '@app/derived': first.outputRef },
        topics: { derived: { module: '@app/derived' } },
        attestations: [att1] as unknown as JsonValue,
      },
    }])
    // 2 builder attestations + 1 audit attestation -> accepted even from non-admin!
    const okOp = await makeOp(logId, nonAdmin, nonAdmin.publicKeyBytes, 'up-ok', 200n, [{
      topic: '$reducers',
      input: {
        imports: { '@app/derived': first.outputRef },
        topics: { derived: { module: '@app/derived' } },
        attestations: [att1, att2, aud] as unknown as JsonValue,
      },
    }])
    const useOp = await makeOp(logId, nonAdmin, nonAdmin.publicKeyBytes, 'use-1', 300n, [{
      topic: 'derived',
      input: { v: 21 },
    }])

    const res = await kernel.materialize([failOp, okOp, useOp])
    expect(res.outcomes[0]!.outcome).toBe('rejected')
    expect(res.outcomes[0]!.rejectionCode).toBe('build_attestation_threshold_unmet')
    expect(res.outcomes[1]!.outcome).toBe('accepted')
    expect(res.outcomes[2]!.outcome).toBe('accepted')
    expect(kernel.topic('derived')).toBe(42)
    kernel.sandbox.dispose()
    sandbox.dispose()
  })
})

import { describe, expect, it } from 'vitest'
import { bytesToHex, utf8 } from '@chronolog/canonical'
import {
  canonicalEventPayload,
  generateEd25519KeyPair,
  genesisLogId,
  operationIdDigest,
  type LogGenesis,
  type OperationCore,
  type TopicUpdate,
} from '@chronolog/protocol'
import { ContentAddressedStore, MemoryBytesStore } from '@chronolog/records'
import { TopicKernel, type KernelOperationInput } from './kernel.js'
import { CAS_BUILTIN_ID, CRYPTO_BUILTIN_ID, QUICKJS_RUNTIME_ID } from './quickjs-sandbox.js'
import { seedStandardModules } from './std-modules.js'

function makeOp(
  logId: Uint8Array,
  author: Uint8Array,
  operationId: string,
  authorTimestampMs: bigint,
  visibility: 'public' | 'encrypted',
  updates: readonly TopicUpdate[],
  nonceByte = 1,
): KernelOperationInput {
  const core: OperationCore = {
    version: 1,
    logId,
    author,
    operationId,
    authorTimestampMs,
    nonce: new Uint8Array(16).fill(nonceByte),
    visibility,
    updates,
  }
  return { opId: operationIdDigest(core), core }
}

describe('Chronolog v2 TopicKernel (Phase 1 Gate 1)', () => {
  it('supports frozen $reducers, governed upgrades, and suffix replay on late earlier ops', async () => {
    const store = new MemoryBytesStore()
    const cas = new ContentAddressedStore({ store })
    const stdImports = await seedStandardModules(cas)

    const counterV1Hash = await cas.put(utf8(`
      export default {
        reduce(state, tx, ctx) {
          if (!ctx.can('writer')) return { ok: false, code: 'unauthorized' };
          const cur = typeof state === 'number' ? state : 0;
          return { ok: true, state: cur + tx.payload.delta, events: [{ topic: 'counter.changed', payload: { value: cur + tx.payload.delta } }] };
        },
        query(state) { return { count: state ?? 0 }; },
      };
    `), [], 'private')

    const counterV2Hash = await cas.put(utf8(`
      export default {
        reduce(state, tx, ctx) {
          if (!ctx.can('writer')) return { ok: false, code: 'unauthorized' };
          const cur = typeof state === 'number' ? state : 0;
          return { ok: true, state: cur + tx.payload.delta * 10 };
        },
      };
    `), [], 'private')

    const admin = await generateEd25519KeyPair()
    const bob = await generateEd25519KeyPair()
    const adminHex = bytesToHex(admin.publicKeyBytes)
    const bobHex = bytesToHex(bob.publicKeyBytes)

    // 1. Frozen $reducers chain (omitting '$reducers' from topics)
    const frozenGenesis: LogGenesis = {
      version: 1,
      privateLog: false,
      initialTopics: {
        $reducers: {
          runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID, 'chronolog:cas': CAS_BUILTIN_ID } },
          imports: { ...stdImports, '@app/counter': `cas:sha256-${counterV1Hash}` },
          topics: {
            $admission: { module: 'chronolog/admission', export: 'attestedAdmission' },
            counter: { module: '@app/counter' },
          },
        },
        $admission: { members: [{ publicKey: adminHex, reader: true, writer: true, administrator: true, publisher: true }] },
        counter: 0,
      },
      limits: { maxMemoryBytes: 16 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16, maxFuel: 200_000 },
      salt: new Uint8Array(16).fill(1),
    }
    const frozenKernel = new TopicKernel({ genesis: frozenGenesis, cas })
    const tryUpgrade = makeOp(frozenKernel.logId, admin.publicKeyBytes, 'upgrade-frozen', 10n, 'public', [
      { topic: '$reducers', input: { imports: { '@app/counter': `cas:sha256-${counterV2Hash}` } } },
    ])
    const frozenRes = await frozenKernel.materialize([tryUpgrade])
    expect(frozenRes.outcomes[0]!.outcome).toBe('rejected')
    expect(frozenRes.outcomes[0]!.rejectionCode).toBe('reducers_frozen')

    // 2. Governed $reducers chain + late earlier upgrade triggering suffix replay
    const govGenesis: LogGenesis = {
      ...frozenGenesis,
      salt: new Uint8Array(16).fill(2),
      initialTopics: {
        ...frozenGenesis.initialTopics,
        $reducers: {
          ...(frozenGenesis.initialTopics.$reducers as Record<string, unknown>),
          topics: {
            $reducers: { module: 'chronolog/admission', export: 'adminOnlyReducers' },
            $admission: { module: 'chronolog/admission', export: 'attestedAdmission' },
            counter: { module: '@app/counter' },
          },
        },
        $admission: {
          members: [
            { publicKey: adminHex, reader: true, writer: true, administrator: true, publisher: true },
            { publicKey: bobHex, reader: true, writer: true, administrator: false, publisher: false },
          ],
        },
      },
    }
    const kernel = new TopicKernel({ genesis: govGenesis, cas })
    const op1 = makeOp(kernel.logId, bob.publicKeyBytes, 'b1', 100n, 'public', [{ topic: 'counter', input: { delta: 2 } }])
    const op2 = makeOp(kernel.logId, bob.publicKeyBytes, 'b2', 300n, 'public', [{ topic: 'counter', input: { delta: 3 } }])
    await kernel.materialize([op1, op2])
    expect(kernel.topic('counter')).toBe(5)
    expect(await kernel.query('counter')).toEqual({ count: 5 })

    // Late-arriving upgrade to counterV2 at t=200 rewinds & replays op2 with v2 (*10)!
    const lateUpgrade = makeOp(kernel.logId, admin.publicKeyBytes, 'u1', 200n, 'public', [
      { topic: '$reducers', input: { imports: { '@app/counter': `cas:sha256-${counterV2Hash}` } } },
    ])
    await kernel.materialize([op1, op2, lateUpgrade])
    expect(kernel.topic('counter')).toBe(32) // 0 + 2 (v1) + 3*10 (v2)
  })

  it('prevents module-level mutable state leakage across reduce(), query(), and suffix replay', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const leakyHash = await cas.put(utf8(`
      let leaked = 0;
      // Global (realm) state must not survive either: each call sees a fresh globalThis.
      const bumpGlobal = () => (globalThis.__leakedGlobal = (globalThis.__leakedGlobal ?? 0) + 1);
      export default {
        reduce(state) {
          leaked += 1;
          return { ok: true, state: (state ?? 0) + leaked * bumpGlobal() };
        },
        query(state) {
          leaked += 100;
          return { state, leaked: leaked * bumpGlobal() };
        },
      };
    `), [], 'public')
    const author = await generateEd25519KeyPair()
    const genesis: LogGenesis = {
      version: 1,
      privateLog: false,
      initialTopics: {
        $reducers: {
          runtime: { js: QUICKJS_RUNTIME_ID, builtins: {} },
          imports: { '@app/leaky': `cas:sha256-${leakyHash}` },
          topics: { leaky: { module: '@app/leaky' } },
        },
        leaky: 0,
      },
      limits: { maxMemoryBytes: 16 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16, maxFuel: 200_000 },
      salt: new Uint8Array(16).fill(3),
    }
    const kernel = new TopicKernel({ genesis, cas })
    const op1 = makeOp(kernel.logId, author.publicKeyBytes, 'o1', 10n, 'public', [{ topic: 'leaky', input: null }])
    const op2 = makeOp(kernel.logId, author.publicKeyBytes, 'o2', 20n, 'public', [{ topic: 'leaky', input: null }])
    await kernel.materialize([op1])
    expect(await kernel.query('leaky')).toEqual({ state: 1, leaked: 100 })
    expect(await kernel.query('leaky')).toEqual({ state: 1, leaked: 100 })
    await kernel.materialize([op1, op2])
    // Because leaked resets to 0 on every invocation, op2 adds 1 (not 2 or 101)
    expect(kernel.topic('leaky')).toBe(2)
  })

  it('suspends uncatchably on MissingDependency even when reducer wraps cas.get in try/catch', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const missingBlobBytes = utf8('secret-payload')
    const casOther = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const blobHash = await casOther.put(missingBlobBytes, [], 'public')

    const sneakyHash = await cas.put(utf8(`
      import { get } from 'chronolog:cas';
      export default {
        reduce(state, tx) {
          try {
            const node = JSON.parse(get(tx.payload.hash));
            return { ok: true, state: { found: node.bytesHex } };
          } catch (e) {
            return { ok: true, state: { swallowed: true } };
          }
        },
      };
    `), [], 'public')

    const author = await generateEd25519KeyPair()
    const genesis: LogGenesis = {
      version: 1,
      privateLog: false,
      initialTopics: {
        $reducers: {
          runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:cas': CAS_BUILTIN_ID } },
          imports: { '@app/sneaky': `cas:sha256-${sneakyHash}` },
          topics: { sneaky: { module: '@app/sneaky' } },
        },
        sneaky: null,
      },
      limits: { maxMemoryBytes: 16 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16, maxFuel: 200_000 },
      salt: new Uint8Array(16).fill(4),
    }
    const kernel = new TopicKernel({ genesis, cas })
    const op = makeOp(kernel.logId, author.publicKeyBytes, 'fetch1', 10n, 'public', [{ topic: 'sneaky', input: { hash: blobHash } }])

    const res1 = await kernel.materialize([op])
    // Try/catch MUST NOT swallow the MissingDependency!
    expect(res1.pendingDependencies).toEqual([`cas/${blobHash}`])
    expect(kernel.topic('sneaky')).toBeNull()

    // Now sync the missing chunk and re-materialize
    await cas.put(missingBlobBytes, [], 'public')
    const res2 = await kernel.materialize([op])
    expect(res2.pendingDependencies).toEqual([])
    expect(res2.outcomes[0]!.outcome).toBe('accepted')
    expect(kernel.topic('sneaky')).toEqual({ found: bytesToHex(missingBlobBytes) })
  })

  it('guarantees blind-host vs full-replica control-state equivalence under adversarial mixed histories & cross-partition opId collision', async () => {
    const fullCas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const blindCas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const stdFull = await seedStandardModules(fullCas)
    await seedStandardModules(blindCas)

    const privHash = await fullCas.put(utf8(`
      export default {
        reduce(state, tx) { return { ok: true, state: (state ?? 0) + 1 }; },
      };
    `), [], 'private')

    const admin = await generateEd25519KeyPair()
    const user = await generateEd25519KeyPair()
    const adminHex = bytesToHex(admin.publicKeyBytes)
    const userHex = bytesToHex(user.publicKeyBytes)

    const genesis: LogGenesis = {
      version: 1,
      privateLog: true,
      initialTopics: {
        $reducers: {
          runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID, 'chronolog:cas': CAS_BUILTIN_ID } },
          imports: { ...stdFull, '@app/priv': `cas:sha256-${privHash}` },
          topics: {
            $admission: { module: 'chronolog/admission', export: 'attestedAdmission' },
            $keys: { module: 'chronolog/keys', export: 'hpkeEpochs' },
            $publications: { module: 'chronolog/publications', export: 'signedReleases' },
            priv: { module: '@app/priv' },
          },
        },
        $admission: { members: [{ publicKey: adminHex, reader: true, writer: true, administrator: true, publisher: true }] },
        $keys: { currentEpoch: -1, epochs: {} },
        $publications: { revision: 0, current: null, history: [] },
        priv: 0,
      },
      limits: { maxMemoryBytes: 16 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16, maxFuel: 200_000 },
      salt: new Uint8Array(16).fill(5),
    }

    const full = new TopicKernel({ genesis, cas: fullCas, blindHostMode: false })
    const blind = new TopicKernel({ genesis, cas: blindCas, blindHostMode: true })

    // 1. Earlier encrypted op uses operationId="shared-id"
    const encOp = makeOp(full.logId, admin.publicKeyBytes, 'shared-id', 10n, 'encrypted', [{ topic: 'priv', input: null }], 1)
    // 2. Later public op reuses operationId="shared-id" (cross-partition collision must NOT suppress public op!)
    const pubGrant = makeOp(full.logId, admin.publicKeyBytes, 'shared-id', 20n, 'public', [
      { topic: '$admission', input: { action: 'setMember', member: { publicKey: userHex, reader: true, writer: true, administrator: false, publisher: true } } },
    ], 2)
    // 3. Adversarial encrypted op trying to mutate $admission (must reject on full replica!)
    const badEncControl = makeOp(full.logId, admin.publicKeyBytes, 'bad-enc', 30n, 'encrypted', [
      { topic: '$admission', input: { action: 'removeMember', publicKey: userHex } },
    ], 3)
    // 4. Adversarial public op trying to mutate private topic (must reject on both!)
    const badPubPriv = makeOp(full.logId, admin.publicKeyBytes, 'bad-pub', 40n, 'public', [
      { topic: 'priv', input: null },
    ], 4)
    // 5. Valid publication by newly granted user
    const pubRelease = makeOp(full.logId, user.publicKeyBytes, 'rel-1', 50n, 'public', [
      { topic: '$publications', input: { action: 'publish', entry: 'index.html', files: [{ path: 'index.html', hash: 'b'.repeat(64), size: 42, type: 'text/html' }] } },
    ], 5)

    const allOps = [encOp, pubGrant, badEncControl, badPubPriv, pubRelease]
    const fullRes = await full.materialize(allOps)
    await blind.materialize(allOps)

    expect(fullRes.outcomes.find(o => o.operationId === 'bad-enc')!.rejectionCode).toBe('partition:encrypted_op_control_topic')
    expect(fullRes.outcomes.find(o => o.operationId === 'bad-pub')!.rejectionCode).toBe('partition:public_op_private_topic')
    expect(full.topic('priv')).toBe(1)

    // Blind host and full replica MUST derive identical control topics!
    expect(blind.topic('$admission')).toEqual(full.topic('$admission'))
    expect(blind.topic('$publications')).toEqual(full.topic('$publications'))
    expect((blind.topic('$publications') as { revision: number }).revision).toBe(1)
  })

  it('rolls back multi-topic operations atomically and verifies checkpoint bootstrap revision parity', async () => {
    const cas1 = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const cas2 = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const modSrc = utf8(`
      export default {
        reduce(state, tx) {
          if (tx.payload && tx.payload.fail) return { ok: false, code: 'forced_fail' };
          return { ok: true, state: (state ?? 0) + (tx.payload?.add ?? 1) };
        },
      };
    `)
    const modHash = await cas1.put(modSrc, [], 'public')
    await cas2.put(modSrc, [], 'public')

    const author = await generateEd25519KeyPair()
    const genesis: LogGenesis = {
      version: 1,
      privateLog: false,
      initialTopics: {
        $reducers: {
          runtime: { js: QUICKJS_RUNTIME_ID, builtins: {} },
          imports: { '@app/m': `cas:sha256-${modHash}` },
          topics: { a: { module: '@app/m' }, b: { module: '@app/m' } },
        },
        a: 0,
        b: 0,
      },
      limits: { maxMemoryBytes: 16 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16, maxFuel: 200_000 },
      salt: new Uint8Array(16).fill(6),
    }

    const logId = genesisLogId(genesis)
    const op1 = makeOp(logId, author.publicKeyBytes, 'op-1', 10n, 'public', [{ topic: 'a', input: { add: 5 } }])
    // Multi-topic atomic rollback: a succeeds, b fails -> a must remain 5!
    const op2Fail = makeOp(logId, author.publicKeyBytes, 'op-2', 20n, 'public', [
      { topic: 'a', input: { add: 100 } },
      { topic: 'b', input: { fail: true } },
    ])
    // Reusing consumed op-2 handle after checkpoint must STILL conflict!
    const op3Reuse = makeOp(logId, author.publicKeyBytes, 'op-2', 30n, 'public', [{ topic: 'a', input: { add: 999 } }], 9)
    const op4Ok = makeOp(logId, author.publicKeyBytes, 'op-4', 40n, 'public', [{ topic: 'b', input: { add: 7 } }])

    const full = new TopicKernel({ genesis, cas: cas1 })
    await full.materialize([op1, op2Fail])
    expect(full.topic('a')).toBe(5)
    expect(full.topic('b')).toBe(0)

    // Capture checkpoint at op2Fail and copy CAS chunks to cas2
    const cpRev = full.revision('local')
    const cpSeenOpsRoot = full.seenOpsRoot // committed lazily; included in gcRoots() once computed
    for (const h of full.gcRoots()) {
      const raw = await cas1.getRaw(h, 'any')
      if (raw !== null) await cas2.putRaw(h, raw, 'public')
    }
    const cpTopics = full.topics

    // Now advance full replica through op3Reuse + op4Ok
    const fullFinal = await full.materialize([op1, op2Fail, op3Reuse, op4Ok])
    expect(fullFinal.outcomes[2]!.rejectionCode).toBe('operation_conflict')
    expect(full.topic('a')).toBe(5)
    expect(full.topic('b')).toBe(7)

    // Bootstrap fresh replica from checkpoint and replay only suffix [op3Reuse, op4Ok]
    const fast = new TopicKernel({ genesis, cas: cas2 })
    await fast.bootstrapFromCheckpoint({
      topics: cpTopics,
      seenOpsRoot: cpSeenOpsRoot,
      historyDigest: cpRev.historyDigest,
      stateRoot: cpRev.stateRoot,
    })
    const fastFinal = await fast.materialize([op3Reuse, op4Ok])
    expect(fastFinal.outcomes[0]!.rejectionCode).toBe('operation_conflict')
    expect(fast.topic('a')).toBe(5)
    expect(fast.topic('b')).toBe(7)
    // Exact stateRoot AND revision.digest parity!
    expect(fast.revision('local').stateRoot).toBe(full.revision('local').stateRoot)
    expect(fast.revision('local').digest).toBe(full.revision('local').digest)
  })

  it('verifies Ed25519 HostAttestation synchronously inside $admission via chronolog:crypto', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const stdImports = await seedStandardModules(cas)
    const admin = await generateEd25519KeyPair()
    const host = await generateEd25519KeyPair()
    const newcomer = await generateEd25519KeyPair()
    const adminHex = bytesToHex(admin.publicKeyBytes)
    const hostHex = bytesToHex(host.publicKeyBytes)
    const newcomerHex = bytesToHex(newcomer.publicKeyBytes)

    const genesis: LogGenesis = {
      version: 1,
      privateLog: true,
      initialTopics: {
        $reducers: {
          runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID } },
          imports: stdImports,
          topics: { $admission: { module: 'chronolog/admission', export: 'attestedAdmission' } },
        },
        $admission: {
          members: [{ publicKey: adminHex, reader: true, writer: true, administrator: true, publisher: true }],
          admission: { hostKey: hostHex },
        },
      },
      limits: { maxMemoryBytes: 16 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16, maxFuel: 200_000 },
      salt: new Uint8Array(16).fill(7),
    }

    const kernel = new TopicKernel({ genesis, cas })
    const attPayload = { logId: bytesToHex(kernel.logId), publicKey: newcomerHex, accountId: 'acct-1', expiresAtMs: 1_000_000 }
    const msg = utf8(canonicalEventPayload(['chronolog/host-attestation/v2', attPayload]))
    const sigBytes = new Uint8Array(await crypto.subtle.sign('Ed25519', host.privateKey, Uint8Array.from(msg).buffer))
    const opGood = makeOp(kernel.logId, admin.publicKeyBytes, 'admit-1', 10n, 'public', [{
      topic: '$admission',
      input: {
        action: 'setMember',
        member: { publicKey: newcomerHex, reader: true, writer: true, administrator: false, publisher: false },
        attestation: { payload: attPayload, signature: bytesToHex(sigBytes) },
      },
    }])
    const res = await kernel.materialize([opGood])
    expect(res.outcomes[0]!.outcome).toBe('accepted')
    expect(await kernel.query('$admission', { publicKey: newcomerHex })).toMatchObject({ publicKey: newcomerHex, writer: true })
  })

  it('enforces public-only partition on ctx.query() and supports multisigAdmission + openAdmission without hardcoded state shape', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const stdImports = await seedStandardModules(cas)
    const s1 = await generateEd25519KeyPair()
    const s2 = await generateEd25519KeyPair()
    const s3 = await generateEd25519KeyPair()
    const guest = await generateEd25519KeyPair()
    const s1Hex = bytesToHex(s1.publicKeyBytes)
    const s2Hex = bytesToHex(s2.publicKeyBytes)
    const s3Hex = bytesToHex(s3.publicKeyBytes)
    const guestHex = bytesToHex(guest.publicKeyBytes)

    // Probe reducer that tries to ctx.query('secret') from a public control topic
    const probeSource = `
      export default {
        reduce(state, tx, ctx) {
          const leaked = ctx.query('secret', { ping: true });
          const isAdmin = ctx.can('administrator');
          return { ok: true, state: { leaked, isAdmin } };
        },
      };
    `
    const secretSource = `
      export default {
        reduce(state, tx) { return { ok: true, state: tx.payload }; },
        query(state) { return { secretValue: state }; },
      };
    `
    const probeHash = await cas.put(utf8(probeSource), [], 'public')
    const secretHash = await cas.put(utf8(secretSource), [], 'public')

    const genesis: LogGenesis = {
      version: 1,
      privateLog: true,
      initialTopics: {
        $reducers: {
          runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID } },
          imports: {
            ...stdImports,
            'app/probe': `cas:sha256-${probeHash}`,
            'app/secret': `cas:sha256-${secretHash}`,
          },
          topics: {
            $admission: { module: 'chronolog/admission', export: 'multisigAdmission' },
            $reducers: { module: 'chronolog/admission', export: 'adminOnlyReducers' },
            $mounts: { module: 'app/probe' },
            secret: { module: 'app/secret' },
          },
        },
        $admission: {
          threshold: 2,
          signers: [s1Hex, s2Hex, s3Hex],
          members: {},
          proposals: {},
        },
        secret: 'TOP_SECRET',
      },
      limits: { maxMemoryBytes: 16 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16, maxFuel: 200_000 },
      salt: new Uint8Array(16).fill(11),
    }

    const full = new TopicKernel({ genesis, cas, blindHostMode: false })
    const blind = new TopicKernel({ genesis, cas, blindHostMode: true })

    // 1. Public control op probing 'secret' via ctx.query() MUST see null (identical on full & blind host)
    const opProbe = makeOp(full.logId, s1.publicKeyBytes, 'probe-1', 10n, 'public', [{ topic: '$mounts', input: {} }])
    // 2. Multisig 2-of-3 proposal to admit guest
    const opPropose = makeOp(full.logId, s1.publicKeyBytes, 'ms-prop-1', 20n, 'public', [{
      topic: '$admission',
      input: {
        action: 'propose',
        id: 'admit-guest',
        kind: 'setMember',
        member: { publicKey: guestHex, reader: true, writer: true, administrator: false, publisher: false },
      },
    }])
    // 3. Second signer approves -> executes atomically!
    const opApprove = makeOp(full.logId, s2.publicKeyBytes, 'ms-app-1', 30n, 'public', [{
      topic: '$admission',
      input: { action: 'approve', id: 'admit-guest' },
    }])

    await full.materialize([opProbe, opPropose])
    expect(full.topic('$mounts')).toEqual({ leaked: null, isAdmin: true })
    // Not admitted after 1 approval (threshold = 2)
    expect(await full.query('$admission', { kind: 'can', capability: 'writer', actor: guestHex })).toBe(false)

    await full.materialize([opProbe, opPropose, opApprove])
    await blind.materialize([opProbe, opPropose, opApprove])

    expect(await full.query('$admission', { kind: 'can', capability: 'writer', actor: guestHex })).toBe(true)
    expect(await blind.query('$admission', { kind: 'can', capability: 'writer', actor: guestHex })).toBe(true)
    expect((await full.query('$admission', { kind: 'roster' }) as { admission: unknown }).admission).toBeNull()
    expect(full.topic('$mounts')).toEqual(blind.topic('$mounts'))
    expect(full.topic('$admission')).toEqual(blind.topic('$admission'))
  })
})

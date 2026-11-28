import { describe, expect, it } from 'vitest'
import { bytesToHex, utf8 } from '@chronolog/canonical'
import {
  buildTreeEpochUpdate,
  epochKeyCommitment,
  generateX25519KeyPair,
  writeKeyTreeToCas,
} from '@chronolog/crypto'
import {
  canonicalEventPayload,
  generateEd25519KeyPair,
  operationIdDigest,
  type JsonValue,
  type LogGenesis,
  type OperationCore,
  type TopicUpdate,
} from '@chronolog/protocol'
import { ContentAddressedStore, MemoryBytesStore } from '@chronolog/records'
import { TopicKernel, type KernelOperationInput } from '../kernel.js'
import { CAS_BUILTIN_ID, CRYPTO_BUILTIN_ID, QUICKJS_RUNTIME_ID } from '../quickjs-sandbox.js'
import { seedStandardModules } from '../std-modules.js'

const hex = (byte: number, bytes = 32) => byte.toString(16).padStart(2, '0').repeat(bytes)
const box = (byte: number) => ({ encapsulatedKey: hex(byte), ciphertext: hex(byte, 48) })
const LIMITS = { maxMemoryBytes: 32 * 1024 * 1024, maxTopicStateBytes: 1_048_576, maxUpdatesPerOp: 16, maxFuel: 400_000 }

interface Party { readonly pk: string; readonly bytes: Uint8Array; readonly wrapKey: string; readonly privateKey: CryptoKey }

async function party(): Promise<Party> {
  const sig = await generateEd25519KeyPair()
  const wrap = await generateX25519KeyPair(false)
  return { pk: bytesToHex(sig.publicKeyBytes), bytes: sig.publicKeyBytes, wrapKey: bytesToHex(wrap.publicKeyBytes), privateKey: sig.privateKey }
}

function member(p: Party, roles: { reader?: boolean; writer?: boolean; administrator?: boolean; publisher?: boolean; scopes?: string[] } = {}): JsonValue {
  return {
    publicKey: p.pk,
    wrapKey: p.wrapKey,
    reader: roles.reader ?? true,
    writer: roles.writer ?? true,
    administrator: roles.administrator ?? false,
    publisher: roles.publisher ?? false,
    ...(roles.scopes ? { scopes: roles.scopes } : {}),
  }
}

class Harness {
  readonly ops: KernelOperationInput[] = []
  #ts = 10n
  #n = 0
  constructor(readonly kernel: TopicKernel) {}

  async submit(author: Party, updates: readonly TopicUpdate[], visibility: 'public' | 'encrypted' = 'public') {
    const core: OperationCore = {
      version: 1,
      logId: this.kernel.logId,
      author: author.bytes,
      operationId: `op-${++this.#n}`,
      authorTimestampMs: (this.#ts += 10n),
      nonce: new Uint8Array(16).fill(this.#n % 256),
      visibility,
      updates,
    }
    const op = { opId: operationIdDigest(core), core }
    this.ops.push(op)
    const res = await this.kernel.materialize(this.ops)
    const outcome = res.outcomes.find(o => o.opId === bytesToHex(op.opId))
    return { outcome: outcome?.outcome ?? 'pending', code: outcome?.rejectionCode ?? null, pending: res.pendingDependencies }
  }
}

async function privateLog(admin: Party, extraMembers: readonly JsonValue[] = [], admissionExtra: Record<string, JsonValue> = {}) {
  const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
  const imports = await seedStandardModules(cas)
  const genesis: LogGenesis = {
    version: 1,
    privateLog: true,
    initialTopics: {
      $reducers: {
        runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID, 'chronolog:cas': CAS_BUILTIN_ID } },
        imports,
        topics: {
          $admission: { module: 'chronolog/admission', export: 'attestedAdmission' },
          $keys: { module: 'chronolog/keys', export: 'hpkeEpochs' },
        },
      },
      $admission: { members: [member(admin, { administrator: true, publisher: true }), ...extraMembers], admission: { hostKey: hex(0), ...admissionExtra } },
      $keys: { currentEpoch: -1, epochs: {} },
    },
    limits: LIMITS,
    salt: crypto.getRandomValues(new Uint8Array(16)),
  }
  const kernel = new TopicKernel({ genesis, cas })
  return { kernel, cas, h: new Harness(kernel) }
}

describe('chronolog/keys lockbox eligibility and write-once grants', () => {
  it('rejects flat epoch boxes addressed to non-readers and enforces recipient wrap-key suites', async () => {
    const admin = await party(), bob = await party(), outsider = await party()
    const { h } = await privateLog(admin, [member(bob)])
    const commitment = hex(0xc0)
    expect(await h.submit(admin, [{ topic: '$keys', input: { action: 'rotateEpoch', epoch: 0, keyCommitment: commitment, boxes: { [admin.pk]: box(1), [outsider.pk]: box(2) } } }]))
      .toMatchObject({ outcome: 'rejected', code: 'box_recipient_not_eligible' })
    // An X-Wing box to a member without a pqWrapKey is rejected.
    const xwing = { suite: 'hpke-xwing-aes256gcm', encapsulatedKey: hex(3, 1120), ciphertext: hex(3, 48) }
    expect(await h.submit(admin, [{ topic: '$keys', input: { action: 'rotateEpoch', epoch: 0, keyCommitment: commitment, boxes: { [bob.pk]: xwing } } }]))
      .toMatchObject({ outcome: 'rejected', code: 'box_recipient_key_missing' })
    expect(await h.submit(admin, [{ topic: '$keys', input: { action: 'rotateEpoch', epoch: 0, keyCommitment: commitment, boxes: { [admin.pk]: box(1), [bob.pk]: box(2) } } }]))
      .toMatchObject({ outcome: 'accepted' })
  })

  it('stops other readers from front-running a newcomer with write-once garbage boxes', async () => {
    const admin = await party(), bob = await party(), carol = await party()
    const { h, kernel } = await privateLog(admin, [member(bob)])
    await h.submit(admin, [{ topic: '$keys', input: { action: 'rotateEpoch', epoch: 0, keyCommitment: hex(0xc0), boxes: { [admin.pk]: box(1), [bob.pk]: box(2) } } }])
    // Admin admits carol (admittedBy = admin); bob is a reader but not carol's admitter.
    expect((await h.submit(admin, [{ topic: '$admission', input: { action: 'setMember', member: member(carol) } }])).outcome).toBe('accepted')
    expect(await kernel.query('$admission', { publicKey: carol.pk })).toMatchObject({ admittedBy: admin.pk })
    expect(await h.submit(bob, [{ topic: '$keys', input: { action: 'grantBoxes', member: carol.pk, epochBoxes: { 0: box(9) } } }]))
      .toMatchObject({ outcome: 'rejected', code: 'grant_not_authorized' })
    expect((await h.submit(admin, [{ topic: '$keys', input: { action: 'grantBoxes', member: carol.pk, epochBoxes: { 0: box(3) } } }])).outcome).toBe('accepted')
    expect(await h.submit(carol, [{ topic: '$keys', input: { action: 'grantBoxes', member: carol.pk, epochBoxes: { 0: box(4) } } }]))
      .toMatchObject({ outcome: 'rejected', code: 'box_already_exists' })
  })

  it('derives tree epoch members from the public CAS leaf directory, ignoring caller claims', async () => {
    const admin = await party(), bob = await party(), outsider = await party()
    const { h, kernel, cas } = await privateLog(admin, [member(bob)])
    const logScope = bytesToHex(kernel.logId)
    const put = (bytes: Uint8Array, links: readonly string[]) => cas.put(bytes, links, 'public')

    const good = await buildTreeEpochUpdate({
      scope: logScope, epoch: 0, updaterPublicKey: admin.pk,
      activeMembers: [{ publicKey: admin.pk, wrapKey: admin.wrapKey }, { publicKey: bob.pk, wrapKey: bob.wrapKey }],
    })
    const goodRef = `cas:sha256-${await writeKeyTreeToCas(good.payload, put)}`
    const res = await h.submit(admin, [{ topic: '$keys', input: {
      action: 'rotateTreeEpoch', epoch: 0, suite: good.payload.suite, keyCommitment: epochKeyCommitment(good.epochKey), treeRef: goodRef,
      // Lies the reducer must ignore:
      activeMembers: [admin.pk], leafCount: 1024,
    } }])
    expect(res.outcome).toBe('accepted')
    const keys = kernel.topic('$keys') as { epochs: Record<string, { activeMembers: string[]; leafCount: number }> }
    expect(keys.epochs['0']!.activeMembers).toEqual([admin.pk, bob.pk].sort())
    expect(keys.epochs['0']!.leafCount).toBe(2)

    const bad = await buildTreeEpochUpdate({
      scope: logScope, epoch: 1, updaterPublicKey: admin.pk,
      activeMembers: [{ publicKey: admin.pk, wrapKey: admin.wrapKey }, { publicKey: outsider.pk, wrapKey: outsider.wrapKey }],
    })
    const badRef = `cas:sha256-${await writeKeyTreeToCas(bad.payload, put)}`
    expect(await h.submit(admin, [{ topic: '$keys', input: {
      action: 'rotateTreeEpoch', epoch: 1, suite: bad.payload.suite, keyCommitment: epochKeyCommitment(bad.epochKey), treeRef: badRef,
    } }])).toMatchObject({ outcome: 'rejected', code: 'tree_member_not_eligible' })
    // Header mismatch (tree written for another epoch).
    expect(await h.submit(admin, [{ topic: '$keys', input: {
      action: 'rotateTreeEpoch', epoch: 1, suite: good.payload.suite, keyCommitment: hex(0xd0), treeRef: goodRef,
    } }])).toMatchObject({ outcome: 'rejected', code: 'tree_header_mismatch' })
    // An unsynced tree suspends the op on a pending CAS dependency instead of trusting it.
    const missing = await h.submit(admin, [{ topic: '$keys', input: {
      action: 'rotateTreeEpoch', epoch: 1, suite: good.payload.suite, keyCommitment: hex(0xd1), treeRef: `cas:sha256-${hex(0xee)}`,
    } }])
    expect(missing.pending).toContain(`cas/${hex(0xee)}`)
  })
})

describe('chronolog/admission removal requires rotation ($keys.policy.rotateOnRemove)', () => {
  it('rejects removing a key holder unless the same op first rotates it out', async () => {
    const admin = await party(), bob = await party()
    const { h, kernel } = await privateLog(admin, [member(bob)])
    await h.submit(admin, [{ topic: '$keys', input: { action: 'rotateEpoch', epoch: 0, keyCommitment: hex(0xc0), boxes: { [admin.pk]: box(1), [bob.pk]: box(2) } } }])
    expect(await h.submit(admin, [{ topic: '$admission', input: { action: 'removeMember', publicKey: bob.pk } }]))
      .toMatchObject({ outcome: 'rejected', code: 'rotation_required' })
    // Demoting reader -> non-reader is a removal too.
    expect(await h.submit(admin, [{ topic: '$admission', input: { action: 'setMember', member: member(bob, { reader: false }) } }]))
      .toMatchObject({ outcome: 'rejected', code: 'rotation_required' })
    // Rotation ordered after the removal does not count.
    expect(await h.submit(admin, [
      { topic: '$admission', input: { action: 'removeMember', publicKey: bob.pk } },
      { topic: '$keys', input: { action: 'rotateEpoch', epoch: 1, keyCommitment: hex(0xc1), boxes: { [admin.pk]: box(3) } } },
    ])).toMatchObject({ outcome: 'rejected', code: 'rotation_required' })
    expect(await h.submit(admin, [
      { topic: '$keys', input: { action: 'rotateEpoch', epoch: 1, keyCommitment: hex(0xc1), boxes: { [admin.pk]: box(3) } } },
      { topic: '$admission', input: { action: 'removeMember', publicKey: bob.pk } },
    ])).toMatchObject({ outcome: 'accepted' })
    expect(await kernel.query('$keys', { kind: 'needsRotation' })).toMatchObject({ needsRotation: false })
  })

  it('allows plain removal when rotateOnRemove is disabled, and needsRotation then reports the stale holder', async () => {
    const admin = await party(), bob = await party()
    const { h, kernel } = await privateLog(admin, [member(bob)])
    await h.submit(admin, [{ topic: '$keys', input: { action: 'setPolicy', policy: { rotateOnRemove: false } } }])
    await h.submit(admin, [{ topic: '$keys', input: { action: 'rotateEpoch', epoch: 0, keyCommitment: hex(0xc0), boxes: { [admin.pk]: box(1), [bob.pk]: box(2) } } }])
    expect((await h.submit(admin, [{ topic: '$admission', input: { action: 'removeMember', publicKey: bob.pk } }])).outcome).toBe('accepted')
    expect(await kernel.query('$keys', { kind: 'needsRotation' })).toMatchObject({ needsRotation: true, staleMembers: [bob.pk] })
  })
})

describe('chronolog/admission host attestations are bound to log and time', () => {
  async function sign(host: Party, payload: JsonValue, domain = 'chronolog/host-attestation/v2') {
    const msg = utf8(canonicalEventPayload([domain, payload]))
    return bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519', host.privateKey, Uint8Array.from(msg).buffer)))
  }

  it('rejects attestations for another log, expired attestations, legacy domains, and wrap-key substitution', async () => {
    const admin = await party(), host = await party(), newcomer = await party()
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const imports = await seedStandardModules(cas)
    const genesis: LogGenesis = {
      version: 1,
      privateLog: true,
      initialTopics: {
        $reducers: {
          runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID, 'chronolog:cas': CAS_BUILTIN_ID } },
          imports,
          topics: { $admission: { module: 'chronolog/admission', export: 'attestedAdmission' } },
        },
        $admission: { members: [member(admin, { administrator: true })], admission: { hostKey: host.pk } },
      },
      limits: LIMITS,
      salt: new Uint8Array(16).fill(3),
    }
    const kernel = new TopicKernel({ genesis, cas })
    const h = new Harness(kernel)
    const logId = bytesToHex(kernel.logId)
    const base = { logId, publicKey: newcomer.pk, wrapKey: newcomer.wrapKey, accountId: 'acct-1', expiresAtMs: 1_000_000 }
    const admit = async (payload: Record<string, JsonValue>, domain?: string, m: JsonValue = member(newcomer)) =>
      h.submit(admin, [{ topic: '$admission', input: { action: 'setMember', member: m, attestation: { payload, signature: await sign(host, payload, domain) } } }])

    expect(await admit({ ...base, logId: hex(0xab) })).toMatchObject({ outcome: 'rejected', code: 'attestation_log_mismatch' })
    expect(await admit({ ...base, expiresAtMs: 5 })).toMatchObject({ outcome: 'rejected', code: 'attestation_expired' })
    expect(await admit(base, 'chronolog/host-attestation/v1')).toMatchObject({ outcome: 'rejected', code: 'attestation_signature_invalid' })
    expect(await admit(base, undefined, { ...(member(newcomer) as Record<string, JsonValue>), wrapKey: hex(0x77) }))
      .toMatchObject({ outcome: 'rejected', code: 'attestation_wrap_key_mismatch' })
    expect((await admit(base)).outcome).toBe('accepted')
  })
})

describe('chronolog/admission roles and history policies', () => {
  it('has no finalizer role; member-quorum is scoped by capability', async () => {
    const admin = await party(), bob = await party()
    const { h, kernel } = await privateLog(admin, [member(bob, { scopes: ['admission:attest'] })])
    const roster = await kernel.query('$admission', { kind: 'roster' }) as Record<string, JsonValue>
    expect(roster).not.toHaveProperty('finalizers')
    expect(JSON.stringify(roster.members)).not.toContain('finalizer')
    expect(await h.submit(admin, [{ topic: '$admission', input: { action: 'schedulePolicy', effectiveAfterMs: 1_000_000, policy: { kind: 'member-quorum', role: 'finalizer', threshold: 1 } } }]))
      .toMatchObject({ outcome: 'rejected', code: 'invalid_admission_policy' })
    expect((await h.submit(admin, [{ topic: '$admission', input: { action: 'schedulePolicy', effectiveAfterMs: 1_000_000, policy: { kind: 'member-quorum', scope: 'admission:attest', threshold: 2 } } }])).outcome)
      .toBe('accepted')
  })

  it('shares one core across presets: open and multisig expose the same roster/query surface', async () => {
    const s1 = await party(), s2 = await party(), guest = await party()
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const imports = await seedStandardModules(cas)
    const mk = (exportName: string, state: JsonValue) => new TopicKernel({
      genesis: {
        version: 1,
        privateLog: false,
        initialTopics: {
          $reducers: {
            runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID, 'chronolog:cas': CAS_BUILTIN_ID } },
            imports,
            topics: { $admission: { module: 'chronolog/admission', export: exportName } },
          },
          $admission: state,
        },
        limits: LIMITS,
        salt: new Uint8Array(16).fill(5),
      },
      cas,
    })
    const multisig = mk('multisigAdmission', { threshold: 1, signers: [s1.pk, s2.pk] })
    const mh = new Harness(multisig)
    expect((await mh.submit(s1, [{ topic: '$admission', input: { action: 'propose', kind: 'setTopicAccess', topic: 'chat', rule: { allowPublicWrite: true } } }])).outcome).toBe('accepted')
    expect(multisig.topic('$admission')).toMatchObject({ topicAccess: { chat: { allowPublicWrite: true } } })
    expect((await mh.submit(guest, [{ topic: '$admission', input: { action: 'rotateWrapKey', wrapKey: guest.wrapKey } }])).code).toBe('member_required')
    expect((await mh.submit(s2, [{ topic: '$admission', input: { action: 'rotateWrapKey', wrapKey: s2.wrapKey } }])).outcome).toBe('accepted')
    expect(await multisig.query('$admission', { publicKey: s2.pk })).toMatchObject({ wrapKey: s2.wrapKey, administrator: true })

    const open = mk('openAdmission', { admins: [s1.pk] })
    const oh = new Harness(open)
    expect((await oh.submit(s1, [{ topic: '$admission', input: { action: 'rotateWrapKey', wrapKey: s1.wrapKey } }])).outcome).toBe('accepted')
    const openRoster = await open.query('$admission', { kind: 'roster' }) as Record<string, JsonValue>
    expect(openRoster).toMatchObject({ mode: 'open', readers: ['*'], administrators: [s1.pk] })
    expect(await open.query('$admission', { kind: 'roster', role: 'blockedAuthors' })).toEqual([])
  })
})

describe('chronolog/vaults lockbox recipients', () => {
  it('rejects rotation boxes to removed members and grants written by other members', async () => {
    const admin = await party(), bob = await party(), carol = await party()
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const imports = await seedStandardModules(cas)
    const kernel = new TopicKernel({
      genesis: {
        version: 1,
        privateLog: false,
        initialTopics: {
          $reducers: {
            runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID, 'chronolog:cas': CAS_BUILTIN_ID } },
            imports,
            topics: {
              $admission: { module: 'chronolog/admission', export: 'attestedAdmission' },
              vaults: { module: 'chronolog/vaults', export: 'privateVaults' },
            },
          },
          $admission: { members: [member(admin, { administrator: true }), member(bob), member(carol)], admission: null },
        },
        limits: LIMITS,
        salt: new Uint8Array(16).fill(6),
      },
      cas,
    })
    const h = new Harness(kernel)
    const v = (input: Record<string, JsonValue>) => [{ topic: 'vaults', input: { vaultId: 'team', ...input } }]
    expect((await h.submit(admin, v({ action: 'createVault', keyCommitment: hex(0xa0), members: [bob.pk, carol.pk], boxes: { [admin.pk]: box(1), [bob.pk]: box(2) } }))).outcome).toBe('accepted')
    // Bob (a member) cannot pre-empt carol's write-once box; carol can write her own.
    expect(await h.submit(bob, v({ action: 'grantBoxes', member: carol.pk, epochBoxes: { 0: box(9) } })))
      .toMatchObject({ outcome: 'rejected', code: 'vault_admin_required' })
    expect((await h.submit(carol, v({ action: 'grantBoxes', member: carol.pk, epochBoxes: { 0: box(3) } }))).outcome).toBe('accepted')
    // Removal must not seal the new epoch to the removed member (or any non-member).
    expect(await h.submit(admin, v({ action: 'removeMember', member: bob.pk, epoch: 1, keyCommitment: hex(0xa1), boxes: { [admin.pk]: box(4), [bob.pk]: box(5) } })))
      .toMatchObject({ outcome: 'rejected', code: 'box_recipient_not_eligible' })
    expect(await h.submit(admin, v({ action: 'rotateVault', epoch: 1, keyCommitment: hex(0xa1), boxes: { [admin.pk]: box(4), [hex(0x99)]: box(5) } })))
      .toMatchObject({ outcome: 'rejected', code: 'box_recipient_not_eligible' })
    expect((await h.submit(admin, v({ action: 'removeMember', member: bob.pk, epoch: 1, keyCommitment: hex(0xa1), boxes: { [admin.pk]: box(4), [carol.pk]: box(6) } }))).outcome).toBe('accepted')
  })
})

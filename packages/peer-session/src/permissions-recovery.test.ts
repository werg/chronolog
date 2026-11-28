import { describe, expect, it } from 'vitest'
import { combineShares, KEY_BOX_SUITE_XWING, splitSecret, verifyEd25519Sync } from '@chronolog/crypto'
import { ANONYMOUS_AUTHOR, decodeEncryptedEnvelope, decodeSignedOperation, envelopeMailboxSigningBytes, verifySignedOperation } from '@chronolog/protocol'
import { MemoryBytesStore } from '@chronolog/records'
import { replayBlindHostControl } from './blind-host.js'
import { openApplicationDevice } from './device.js'
import { createLogGenesis } from './genesis.js'
import { createApplicationSession } from './runtime.js'

describe('Phase 4: Scoped/expiring permissions, compartments, anti-spam, and threshold social recovery', () => {
  it('splits and reconstructs 32-byte secrets via GF(256) Shamir Secret Sharing', () => {
    const secret = crypto.getRandomValues(new Uint8Array(32))
    const shares = splitSecret(secret, 2, 3)
    expect(shares).toHaveLength(3)
    expect(combineShares([shares[0]!, shares[1]!])).toEqual(secret)
    expect(combineShares([shares[0]!, shares[2]!])).toEqual(secret)
    expect(combineShares([shares[1]!, shares[2]!])).toEqual(secret)
    expect(combineShares(shares)).toEqual(secret)
    // A single share never equals the secret
    expect(shares[0]!.bytes).not.toEqual(secret)
  })

  it('recovers a lost owner device via 2-of-3 non-reader guardians without ever leaking app data to guardians', async () => {
    const owner = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const g1 = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const g2 = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const g3 = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const freshDevice = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    const created = await createLogGenesis({
      creator: {
        publicKey: owner.identity.publicKey,
        wrapKey: owner.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: true,
      },
      privateLog: true,
      topics: {
        db: { module: 'chronolog/sql' },
      },
    })

    const sOwner = await createApplicationSession({
      device: owner,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys: new Map([[0, created.epoch0Key!]]),
    })
    const sG1 = await createApplicationSession({ device: g1, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sG2 = await createApplicationSession({ device: g2, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sFresh = await createApplicationSession({ device: freshDevice, genesis: created.genesisBytes, casNodes: created.casNodes })

    try {
      // Owner writes private data
      await (await sOwner.command('db:migrate', {
        statements: ['CREATE TABLE secrets (id TEXT PRIMARY KEY, val TEXT NOT NULL)'],
      })).materialized()
      await (await sOwner.command('db:exec', {
        sql: 'INSERT INTO secrets VALUES (?, ?)',
        params: ['k1', 'family-heirloom-recipe'],
      })).materialized()

      // Owner configures 3 trusted backup contacts (threshold 2) — NONE of them are page readers!
      const setup = await sOwner.setupSocialRecovery({
        threshold: 2,
        guardians: [
          { publicKey: g1.identity.publicKey, wrapKey: g1.wrapKey.publicKey, label: 'Mom' },
          { publicKey: g2.identity.publicKey, wrapKey: g2.wrapKey.publicKey, label: 'Best friend' },
          { publicKey: g3.identity.publicKey, wrapKey: g3.wrapKey.publicKey, label: 'Hardware backup' },
        ],
      })
      expect((await setup.materialized()).outcome).toBe('accepted')

      // Sync owner's facts to guardians & fresh device
      const ownerFacts = await sOwner.exportFacts()
      await sG1.mergeFacts(ownerFacts)
      await sG2.mergeFacts(ownerFacts)
      await sFresh.mergeFacts(ownerFacts)

      // Verify guardian g1 CANNOT read private app data!
      const g1Tables = (await sG1.query('db', { kind: 'tables' })).value as { tables: unknown[] }
      expect(g1Tables.tables).toEqual([])
      expect(sG1.hasEpochKey(0)).toBe(false)

      // Owner lost phone -> fresh device requests recovery with a 6-digit match code!
      const req = await sFresh.requestSocialRecovery({ label: 'New Pixel' })
      expect(req.verificationCode).toMatch(/^\d{6}$/)
      expect((await req.operation.materialized()).outcome).toBe('accepted')

      // Guardian 1 & Guardian 2 approve
      await sG1.mergeFacts(await sFresh.exportFacts())
      const ap1 = await sG1.approveSocialRecovery(req.requestId)
      expect((await ap1.materialized()).outcome).toBe('accepted')

      await sG2.mergeFacts(await sG1.exportFacts())
      const ap2 = await sG2.approveSocialRecovery(req.requestId)
      expect((await ap2.materialized()).outcome).toBe('accepted')

      // Fresh device receives both guardian approvals, completes recovery, and decrypts the full private DB!
      await sFresh.mergeFacts(await sG2.exportFacts())
      const restored = await sFresh.completeSocialRecovery()
      expect(restored.restoredEpochs).toBe(1)
      expect(sFresh.isAdministrator(freshDevice.identity.publicKey)).toBe(true)

      const recoveredRows = (await sFresh.query('db', { sql: 'SELECT id, val FROM secrets' })).value as { rows: unknown[][] }
      expect(recoveredRows.rows).toEqual([['k1', 'family-heirloom-recipe']])
    } finally {
      await sOwner.close()
      await sG1.close()
      await sG2.close()
      await sFresh.close()
    }
  })

  it('enforces scoped & auto-expiring passes, compartment key rings, and openMembers vouching anti-spam', async () => {
    const admin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const guest = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const created = await createLogGenesis({
      creator: {
        publicKey: admin.identity.publicKey,
        wrapKey: admin.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: true,
      },
      privateLog: true,
      topics: {
        shared: { module: 'chronolog/sql' },
        admin_vault: { module: 'chronolog/crdt', export: 'lwwMap' },
      },
    })

    const sAdmin = await createApplicationSession({
      device: admin,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys: new Map([[0, created.epoch0Key!]]),
    })
    const sGuest = await createApplicationSession({ device: guest, genesis: created.genesisBytes, casNodes: created.casNodes })
    try {
      // Admit guest with narrow scope ['drafts:write'] and auto-expiry at t=5000
      await (await sAdmin.admitMember({
        publicKey: guest.identity.publicKey,
        wrapKey: guest.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: false,
        publisher: false,
        finalizer: false,
        scopes: ['drafts:write'],
        expiresAtMs: 5000,
        authorTimestampMs: 500n,
      })).materialized()

      // Create an 'admins' compartment bound to 'admin_vault' sealed ONLY to admin!
      const comp = await sAdmin.createCompartment('admins', {
        topics: ['admin_vault'],
        members: [{ publicKey: admin.identity.publicKey, wrapKey: admin.wrapKey.publicKey }],
        authorTimestampMs: 600n,
      })
      expect((await comp.operation.materialized()).outcome).toBe('accepted')

      await (await sAdmin.command('shared:migrate', {
        statements: ['CREATE TABLE drafts (id TEXT PRIMARY KEY, body TEXT NOT NULL)'],
      }, { authorTimestampMs: 1000n })).materialized()

      // Admin writes a confidential entry into admin_vault
      const secretOp = await sAdmin.command('admin_vault:set', { key: 'salary_band', value: 'L7' }, { authorTimestampMs: 1500n })
      expect((await secretOp.materialized()).outcome).toBe('accepted')

      // Sync to guest -> guest reads shared DB, CANNOT decrypt admin_vault!
      await sGuest.mergeFacts(await sAdmin.exportFacts())
      expect((await sGuest.query('admin_vault')).value).toEqual({})
      expect((await sAdmin.query('admin_vault')).value).toEqual({ salary_band: 'L7' })

      // Guest writes with allowed scope before expiry -> ACCEPTED
      const okWrite = await sGuest.command('shared:exec', {
        requiredScope: 'drafts:write',
        sql: 'INSERT INTO drafts VALUES (?, ?)',
        params: ['d1', 'hello'],
      }, { authorTimestampMs: 2000n })
      expect((await okWrite.materialized()).outcome).toBe('accepted')

      // Guest tries unauthorized scope -> REJECTED ('scope_required')
      const badScope = await sGuest.command('shared:exec', {
        requiredScope: 'payroll:write',
        sql: 'INSERT INTO drafts VALUES (?, ?)',
        params: ['d2', 'sneaky'],
      }, { authorTimestampMs: 2100n })
      expect((await badScope.materialized()).rejectionCode).toBe('scope_required')

      // Guest tries writing AFTER expiresAtMs (t=6000 > 5000) with zero admin online -> REJECTED ('writer_required')!
      const expiredWrite = await sGuest.command('shared:exec', {
        requiredScope: 'drafts:write',
        sql: 'INSERT INTO drafts VALUES (?, ?)',
        params: ['d3', 'too late'],
      }, { authorTimestampMs: 6000n })
      expect((await expiredWrite.materialized()).rejectionCode).toBe('writer_required')
    } finally {
      await sAdmin.close()
      await sGuest.close()
    }

    // Quiet anti-spam vouching in openMembers
    const pubAdmin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const newcomer = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const pubGen = await createLogGenesis({
      creator: {
        publicKey: pubAdmin.identity.publicKey,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: true,
      },
      privateLog: false,
      topics: {
        $admission: {
          module: 'chronolog/admission',
          export: 'openAdmission',
          initialState: { admins: [pubAdmin.identity.publicKey], members: [], openRead: true, openWrite: true, admission: null },
        },
        board: { module: 'chronolog/crdt', export: 'lwwMap' },
      },
    })
    const sPubAdmin = await createApplicationSession({ device: pubAdmin, genesis: pubGen.genesisBytes, casNodes: pubGen.casNodes })
    const sNewcomer = await createApplicationSession({ device: newcomer, genesis: pubGen.genesisBytes, casNodes: pubGen.casNodes })
    try {
      await (await sPubAdmin.submit({
        visibility: 'public',
        updates: [{ topic: '$admission', input: { action: 'setAntiSpam', antiSpam: { requireVouch: true } } }],
        authorTimestampMs: 1000n,
      })).materialized()

      await sNewcomer.mergeFacts(await sPubAdmin.exportFacts())
      const blockedPost = await sNewcomer.command('board:set', { key: 'hi', value: 'spam?' }, { authorTimestampMs: 2000n })
      expect((await blockedPost.materialized()).rejectionCode).toBe('writer_required')

      // Admin vouches for newcomer -> subsequent post succeeds!
      await (await sPubAdmin.submit({
        visibility: 'public',
        updates: [{ topic: '$admission', input: { action: 'vouchAuthor', publicKey: newcomer.identity.publicKey } }],
        authorTimestampMs: 2500n,
      })).materialized()
      await sNewcomer.mergeFacts(await sPubAdmin.exportFacts())
      const allowedPost = await sNewcomer.command('board:set', { key: 'hi', value: 'verified human!' }, { authorTimestampMs: 3000n })
      expect((await allowedPost.materialized()).outcome).toBe('accepted')
    } finally {
      await sPubAdmin.close()
      await sNewcomer.close()
    }
  })

  it('supports hybrid PQ X-Wing epochs, anonymous-author padded envelopes, blind-host mailbox verification, sealFor/unseal, write-once boxes, and kernel ring isolation', async () => {
    const admin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const bob = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const carol = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    expect(admin.pqWrapKey?.publicKey).toMatch(/^[0-9a-f]{2432}$/u)

    const created = await createLogGenesis({
      creator: {
        publicKey: admin.identity.publicKey,
        wrapKey: admin.wrapKey.publicKey,
        pqWrapKey: admin.pqWrapKey!.publicKey,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: true,
      },
      privateLog: true,
      keysPolicy: {
        minSuite: KEY_BOX_SUITE_XWING,
        paddingBucketBytes: 512,
        hideEnvelopeAuthor: true,
      },
      topics: {
        notes: { module: 'chronolog/crdt', export: 'lwwMap' },
        vault: { module: 'chronolog/crdt', export: 'lwwMap' },
      },
    })

    const sAdmin = await createApplicationSession({
      device: admin,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys: new Map([[0, created.epoch0Key!]]),
    })
    const sBob = await createApplicationSession({ device: bob, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sCarol = await createApplicationSession({ device: carol, genesis: created.genesisBytes, casNodes: created.casNodes })

    try {
      // Admit Bob with hybrid PQ X-Wing key -> epoch 0 is created with suite hpke-xwing-aes256gcm + mailboxVerifyKey
      const admitBob = await sAdmin.admitMember({
        publicKey: bob.identity.publicKey,
        wrapKey: bob.wrapKey.publicKey,
        pqWrapKey: bob.pqWrapKey!.publicKey,
      })
      expect((await admitBob.materialized()).outcome).toBe('accepted')
      expect(sAdmin.keysState().epochs['0']?.suite).toBe(KEY_BOX_SUITE_XWING)
      expect(sAdmin.keysState().epochs['0']?.mailboxVerifyKey).toMatch(/^[0-9a-f]{64}$/u)

      // Downgrade attempt below minSuite must be rejected by $keys
      const badRotate = await sAdmin.submit({
        visibility: 'public',
        awaitMaterialized: true,
        updates: [{
          topic: '$keys',
          input: {
            action: 'rotateEpoch',
            epoch: 1,
            suite: 'hpke-x25519-aes256gcm',
            keyCommitment: 'a'.repeat(64),
            boxes: {},
          },
        }],
      })
      expect((await badRotate.materialized()).rejectionCode).toBe('suite_below_minimum')

      // Sync to Bob; Bob unseals PQ X-Wing epoch 0 and writes a private note
      await sBob.mergeFacts(await sAdmin.exportFacts())
      expect(sBob.hasEpochKey(0)).toBe(true)

      const bobOp = await sBob.command('notes:set', { key: 'secret', value: 'quantum-safe' })
      expect((await bobOp.materialized()).outcome).toBe('accepted')

      // Inspect raw encrypted envelope: outer author is zeroed (ANONYMOUS_AUTHOR), padded to power-of-2 bucket, and signed by epoch mailbox key!
      const bobFacts = await sBob.exportFacts()
      expect(bobFacts.encryptedEnvelopes.length).toBe(1)
      const rawEnv = decodeEncryptedEnvelope(bobFacts.encryptedEnvelopes[0]!)
      expect(rawEnv.author).toEqual(ANONYMOUS_AUTHOR)
      expect(rawEnv.suite).toBe('hkdf-aes-256-gcm')
      expect(rawEnv.nonce).toHaveLength(24)
      expect(rawEnv.ciphertext.byteLength % 512).toBe(16) // 512-byte padded plaintext + 16-byte GCM tag
      expect(rawEnv.mailboxTag).toHaveLength(64)

      // Blind host replays public control ops and verifies mailboxTag strictly against derived mailboxVerifyKey without knowing Bob wrote it!
      const ctrl = await sAdmin.exportPublicControlFacts()
      const verifiedPublicOps = await Promise.all(ctrl.publicOps.map(async raw => {
        const v = await verifySignedOperation(decodeSignedOperation(raw))
        return { opId: v.opId, core: v.core, verified: true as const }
      }))
      const blind = await replayBlindHostControl({
        genesis: created.genesis,
        publicOps: verifiedPublicOps,
        publicCasNodes: ctrl.casNodes.map(n => ({ hash: n.hash, bytes: n.bytes })),
      })
      const mbKeyHex = blind.mailboxVerifyKeys.default?.['0']
      expect(mbKeyHex).toBe(sAdmin.keysState().epochs['0']!.mailboxVerifyKey!)
      expect(verifyEd25519Sync(
        Uint8Array.from(Buffer.from(mbKeyHex!, 'hex')),
        envelopeMailboxSigningBytes(rawEnv),
        rawEnv.mailboxTag!,
      )).toBe(true)

      // Admin decrypts Bob's anonymous envelope and verifies Bob is the true inner author!
      await sAdmin.mergeFacts(bobFacts)
      expect(sAdmin.topic('notes')).toMatchObject({ entries: { secret: { value: 'quantum-safe' } } })

      // Non-admin write-once lockbox protection: Bob cannot overwrite admin's existing epoch 0 box!
      const overwriteAttempt = await sBob.submit({
        visibility: 'public',
        awaitMaterialized: true,
        updates: [{
          topic: '$keys',
          input: {
            action: 'grantBoxes',
            member: admin.identity.publicKey,
            epochBoxes: { '0': { suite: KEY_BOX_SUITE_XWING, encapsulatedKey: '00', ciphertext: '00' } },
          },
        }],
      })
      expect((await overwriteAttempt.materialized()).rejectionCode).toBe('box_already_exists')

      // Self-service wrap key rotation for Bob
      const rotWrap = await sBob.rotateWrapKey()
      expect((await rotWrap.materialized()).outcome).toBe('accepted')

      // Selective per-recipient sealFor / unseal: admin seals a secret strictly to Bob (Carol cannot open)
      await sAdmin.admitMember({
        publicKey: carol.identity.publicKey,
        wrapKey: carol.wrapKey.publicKey,
        pqWrapKey: carol.pqWrapKey!.publicKey,
      })
      const sealed = await sAdmin.sealFor([bob.identity.publicKey], { ssn: '000-00-0000' })
      expect(sealed.boxes[bob.identity.publicKey]?.suite).toBe(KEY_BOX_SUITE_XWING)
      expect(await sBob.unseal(sealed)).toEqual({ ssn: '000-00-0000' })
      await expect(sCarol.unseal(sealed)).rejects.toThrow('SEALED_BOX_NOT_A_RECIPIENT')

      // On-log org group policy stored in $admission
      const setGp = await sAdmin.submit({
        visibility: 'public',
        awaitMaterialized: true,
        updates: [{
          topic: '$admission',
          input: {
            action: 'setGroupPolicy',
            groupPolicy: { revision: 1, rules: [{ ruleId: 'eng', group: 'github-org:acme', role: 'writer' }] },
          },
        }],
      })
      expect((await setGp.materialized()).outcome).toBe('accepted')
      expect((sAdmin.permissions().admission as { groupPolicy?: unknown } | null)?.groupPolicy).toEqual({
        revision: 1,
        rules: [{ ruleId: 'eng', group: 'github-org:acme', role: 'writer' }],
      })

      // Compartment ring isolation enforced at kernel level: bind `vault` to `admins` ring
      const comp = await sAdmin.createCompartment('admins', {
        topics: ['vault'],
        members: [{ publicKey: admin.identity.publicKey, pqWrapKey: admin.pqWrapKey!.publicKey }],
      })
      expect((await comp.operation.materialized()).outcome).toBe('accepted')
      const vaultOk = await sAdmin.command('vault:set', { key: 'k', value: 'admin-only' })
      expect((await vaultOk.materialized()).outcome).toBe('accepted')
      // Mixing default ring (`notes`) and compartment ring (`vault`) fails fast
      await expect(sAdmin.submit({
        updates: [
          { topic: 'notes', input: { action: 'set', key: 'a', value: 1 } },
          { topic: 'vault', input: { action: 'set', key: 'b', value: 2 } },
        ],
      })).rejects.toThrow('OPERATION_CROSS_RING_FORBIDDEN')
    } finally {
      await sAdmin.close()
      await sBob.close()
      await sCarol.close()
    }
  })
})

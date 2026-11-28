import { describe, expect, it } from 'vitest'
import { combineShares, epochKeyCommitment, KEY_BOX_SUITE_XWING, splitSecret, verifyEd25519Sync } from '@chronolog/crypto'
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

      // Non-admin lockbox authorization & write-once protection:
      // 1. Bob cannot grant boxes for admin -> grant_not_authorized
      const overwriteAdmin = await sBob.submit({
        visibility: 'public',
        awaitMaterialized: true,
        updates: [{
          topic: '$keys',
          input: {
            action: 'grantBoxes',
            member: admin.identity.publicKey,
            epochBoxes: { '0': { suite: KEY_BOX_SUITE_XWING, encapsulatedKey: '00'.repeat(1120), ciphertext: '00'.repeat(48) } },
          },
        }],
      })
      expect((await overwriteAdmin.materialized()).rejectionCode).toBe('grant_not_authorized')
      // 2. Bob cannot overwrite his own existing epoch 0 box -> box_already_exists
      const overwriteSelf = await sBob.submit({
        visibility: 'public',
        awaitMaterialized: true,
        updates: [{
          topic: '$keys',
          input: {
            action: 'grantBoxes',
            member: bob.identity.publicKey,
            epochBoxes: { '0': { suite: KEY_BOX_SUITE_XWING, encapsulatedKey: '00'.repeat(1120), ciphertext: '00'.repeat(48) } },
          },
        }],
      })
      expect((await overwriteSelf.materialized()).rejectionCode).toBe('box_already_exists')

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

  it('supports mixed X-Wing + X25519 epoch admission, O(log N) Key-Tagged TreeKEM, Private Vaults, and SQL write-time RLS crypto helpers', async () => {
    const admin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const alice = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const bob = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const x25519OnlyAgent = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const extraPeers = await Promise.all(Array.from({ length: 5 }, () => openApplicationDevice({ store: new MemoryBytesStore(), create: true })))

    const sqlReducer = `
      import { openDb } from 'chronolog:sqlite';
      import { applyRls, sealRecipientsPolicy, vaultBoxPolicy } from 'chronolog/rls';
      export default {
        reduce(state, tx, ctx) {
          if (!ctx.can('writer')) return { ok: false, code: 'writer_required' };
          const db = openDb(state && state.dbRoot ? state.dbRoot : null);
          const input = tx.payload || {};
          if (input.action === 'init') {
            db.exec('CREATE TABLE allowed_readers (pk TEXT PRIMARY KEY)', [], { mode: 'admin' });
            db.exec('CREATE TABLE secrets (id TEXT PRIMARY KEY, secret_box TEXT NOT NULL)', [], { mode: 'admin' });
            db.exec('CREATE TABLE vault_docs (id TEXT PRIMARY KEY, vault_id TEXT NOT NULL, payload TEXT NOT NULL)', [], { mode: 'admin' });
            applyRls(db, {
              secrets: { insert: sealRecipientsPolicy('secret_box', 'SELECT pk FROM allowed_readers') },
              vault_docs: { insert: vaultBoxPolicy('payload', 'vault_id', 'vaults') },
            });
            for (const pk of input.allowed || []) {
              db.exec('INSERT INTO allowed_readers (pk) VALUES (?)', [pk], { mode: 'admin' });
            }
            return { ok: true, state: { dbRoot: db.commit() } };
          }
          if (input.action === 'putSecret') {
            db.exec('INSERT INTO secrets (id, secret_box) VALUES (?, ?)', [input.id, input.secretBox], { mode: 'user' });
            return { ok: true, state: { dbRoot: db.commit() } };
          }
          if (input.action === 'putVaultDoc') {
            db.exec('INSERT INTO vault_docs (id, vault_id, payload) VALUES (?, ?, ?)', [input.id, input.vaultId, input.payload], { mode: 'user' });
            return { ok: true, state: { dbRoot: db.commit() } };
          }
          return { ok: false, code: 'unknown_action' };
        },
        query(state, input) {
          if (!state || !state.dbRoot) return { rows: [] };
          const db = openDb(state.dbRoot);
          return db.query(input.sql, input.params || [], { format: 'objects' });
        },
      };
    `

    const created = await createLogGenesis({
      creator: {
        publicKey: admin.identity.publicKey,
        wrapKey: admin.wrapKey.publicKey,
        pqWrapKey: admin.pqWrapKey!.publicKey,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
      },
      privateLog: true,
      imports: { 'app/secure-sql': sqlReducer },
      topics: {
        vaults: { module: 'chronolog/vaults' },
        db: { module: 'app/secure-sql' },
      },
    })

    const sAdmin = await createApplicationSession({
      device: admin,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys: new Map([[0, created.epoch0Key!]]),
    })
    const sAlice = await createApplicationSession({ device: alice, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sBob = await createApplicationSession({ device: bob, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sAgent = await createApplicationSession({ device: x25519OnlyAgent, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sExtras = await Promise.all(extraPeers.map(d => createApplicationSession({ device: d, genesis: created.genesisBytes, casNodes: created.casNodes })))

    try {
      // 1. Mixed X-Wing + X25519 epoch 0 admission (regression test for native agent with wrapKey only!)
      await (await sAdmin.admitMember({ publicKey: alice.identity.publicKey, wrapKey: alice.wrapKey.publicKey, pqWrapKey: alice.pqWrapKey!.publicKey })).materialized()
      expect(sAdmin.keysState().epochs['0']?.suite).toBe(KEY_BOX_SUITE_XWING)
      await (await sAdmin.admitMember({ publicKey: bob.identity.publicKey, wrapKey: bob.wrapKey.publicKey, pqWrapKey: bob.pqWrapKey!.publicKey })).materialized()
      // Native agent has ONLY X25519 wrapKey (no pqWrapKey) — must still open epoch 0 cleanly!
      await (await sAdmin.admitMember({ publicKey: x25519OnlyAgent.identity.publicKey, wrapKey: x25519OnlyAgent.wrapKey.publicKey })).materialized()
      await sAgent.mergeFacts(await sAdmin.exportFacts())
      expect(sAgent.hasEpochKey(0)).toBe(true)

      for (const p of extraPeers) {
        await (await sAdmin.admitMember({ publicKey: p.identity.publicKey, wrapKey: p.wrapKey.publicKey, pqWrapKey: p.pqWrapKey!.publicKey })).materialized()
      }

      // 2. Sub-linear O(log N) Key-Tagged TreeKEM rotation over 9 members
      const tree1 = await sAdmin.rotateTreeEpoch()
      expect((await tree1.operation.materialized()).outcome).toBe('accepted')
      expect(tree1.epoch).toBe(1)

      const facts1 = await sAdmin.exportFacts()
      await sAlice.mergeFacts(facts1)
      await sBob.mergeFacts(facts1)
      await sAgent.mergeFacts(facts1)
      for (const s of sExtras) await s.mergeFacts(facts1)
      expect(sAlice.hasEpochKey(1)).toBe(true)
      expect(sBob.hasEpochKey(1)).toBe(true)
      expect(sAgent.hasEpochKey(1)).toBe(true)
      expect(sExtras[0]!.hasEpochKey(1)).toBe(true)

      // Default rotateOnRemove: true blocks removing a reader without rotating in the same op!
      const blockedRemove = await (await sAdmin.removeMember(extraPeers[4]!.identity.publicKey, { rotateEpoch: false })).materialized()
      expect(blockedRemove.outcome).toBe('rejected')
      expect(blockedRemove.rejectionCode).toBe('rotation_required')

      // With rotateOnRemove: false, removing without rotating succeeds and keysNeedsRotation() detects the stale leaf!
      await (await sAdmin.setKeysPolicy({ rotateOnRemove: false })).materialized()
      expect((await (await sAdmin.removeMember(extraPeers[4]!.identity.publicKey, { rotateEpoch: false })).materialized()).outcome).toBe('accepted')
      const needs = await sAdmin.keysNeedsRotation()
      expect(needs.needsRotation).toBe(true)
      expect(needs.staleMembers).toContain(extraPeers[4]!.identity.publicKey)

      // Sub-linear healing TreeKEM rotation excludes extraPeers[4] in O(log N) boxes!
      const tree2 = await sAdmin.rotateTreeEpoch()
      expect((await tree2.operation.materialized()).outcome).toBe('accepted')
      expect(tree2.epoch).toBe(2)
      console.log("COPATH", tree1.copathBoxes, tree2.copathBoxes)
      expect(tree2.copathBoxes).toBeLessThanOrEqual(8)
      expect((await sAdmin.keysNeedsRotation()).needsRotation).toBe(false)

      const facts2 = await sAdmin.exportFacts()
      await sAlice.mergeFacts(facts2)
      await sBob.mergeFacts(facts2)
      await sExtras[0]!.mergeFacts(facts2)
      await sExtras[4]!.mergeFacts(facts2)
      expect(sAlice.hasEpochKey(2)).toBe(true)
      expect(sBob.hasEpochKey(2)).toBe(true)
      expect(sExtras[0]!.hasEpochKey(2)).toBe(true)
      expect(sExtras[4]!.hasEpochKey(2)).toBe(false)

      // 3. Private Capability Vaults + SQL write-time RLS (sealRecipientsPolicy & vaultBoxPolicy)
      await (await sAdmin.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'db', input: { action: 'init', allowed: [admin.identity.publicKey, alice.identity.publicKey] } }],
      })).materialized()

      // sealRecipientsPolicy: sealing strictly to Alice succeeds; leaking to Bob is rejected by SQLite RLS!
      const okSealed = await sAdmin.sealFor([alice.identity.publicKey], { salary: 200_000 })
      const okSec = await sAdmin.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'db', input: { action: 'putSecret', id: 's1', secretBox: JSON.stringify(okSealed) } }],
      })
      expect((await okSec.materialized()).outcome).toBe('accepted')

      const badSealed = await sAdmin.sealFor([alice.identity.publicKey, bob.identity.publicKey], { salary: 200_000 })
      const badSec = await sAdmin.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'db', input: { action: 'putSecret', id: 's2', secretBox: JSON.stringify(badSealed) } }],
      })
      expect((await badSec.materialized()).outcome).toBe('rejected')

      // Private vault 'deal:acme' with ONLY [admin, alice] (invisible to blind host & Bob!)
      expect((await (await sAdmin.vaults.create('deal:acme', { members: [alice.identity.publicKey] })).materialized()).outcome).toBe('accepted')
      const vBox0 = await sAdmin.vaults.seal('deal:acme', { price: '$2M' })
      expect((await (await sAdmin.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'db', input: { action: 'putVaultDoc', id: 'd1', vaultId: 'deal:acme', payload: JSON.stringify(vBox0) } }],
      })).materialized()).outcome).toBe('accepted')

      // Sync to Alice & Bob: Alice unseals d1; Bob cannot unseal d1 AND cannot write to deal:acme (vaultBoxPolicy)!
      const vFacts1 = await sAdmin.exportFacts()
      await sAlice.mergeFacts(vFacts1)
      await sBob.mergeFacts(vFacts1)
      expect(sAlice.vaults.hasKey('deal:acme', 0)).toBe(true)
      expect(sBob.vaults.hasKey('deal:acme', 0)).toBe(false)

      const aliceRows = ((await sAlice.query('db', { sql: 'SELECT id, vault_id, payload FROM vault_docs' })).value as { rows: unknown[][] }).rows
      expect(await sAlice.vaults.unsealRows(aliceRows)).toEqual([['d1', 'deal:acme', { price: '$2M' }]])
      expect(await sAlice.vaults.unsealRows([{ id: 'd1', vault_id: 'deal:acme', payload: vBox0 }])).toEqual([
        { id: 'd1', vault_id: 'deal:acme', payload: { price: '$2M' } },
      ])
      const bobRows = ((await sBob.query('db', { sql: 'SELECT id, vault_id, payload FROM vault_docs' })).value as { rows: unknown[][] }).rows
      expect(await sBob.vaults.unsealRows(bobRows)).toEqual([['d1', 'deal:acme', null]])

      const bobForbiddenWrite = await sBob.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'db', input: { action: 'putVaultDoc', id: 'd-forged', vaultId: 'deal:acme', payload: JSON.stringify(vBox0) } }],
      })
      expect((await bobForbiddenWrite.materialized()).outcome).toBe('rejected')

      // O(1) add Bob to 'deal:acme' -> Bob can immediately unseal d1!
      await (await sAdmin.vaults.addMember('deal:acme', bob.identity.publicKey)).materialized()
      await sBob.mergeFacts(await sAdmin.exportFacts())
      expect(sBob.vaults.hasKey('deal:acme', 0)).toBe(true)
      expect(await sBob.vaults.unsealRows(bobRows)).toEqual([['d1', 'deal:acme', { price: '$2M' }]])

      // Remove Bob from 'deal:acme' -> rotates vault to epoch 1 -> Bob cannot unseal epoch 1 doc d2 (forward secrecy)!
      const rem = await sAdmin.vaults.removeMember('deal:acme', bob.identity.publicKey)
      expect(rem.epoch).toBe(1)
      const vBox1 = await sAdmin.vaults.seal('deal:acme', { price: '$3M' })
      expect((await (await sAdmin.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'db', input: { action: 'putVaultDoc', id: 'd2', vaultId: 'deal:acme', payload: JSON.stringify(vBox1) } }],
      })).materialized()).outcome).toBe('accepted')

      const vFacts2 = await sAdmin.exportFacts()
      await sAlice.mergeFacts(vFacts2)
      await sBob.mergeFacts(vFacts2)
      expect(sAlice.vaults.hasKey('deal:acme', 1)).toBe(true)
      expect(sBob.vaults.hasKey('deal:acme', 1)).toBe(false)
      const d2Alice = ((await sAlice.query('db', { sql: "SELECT id, payload FROM vault_docs WHERE id = 'd2'" })).value as { rows: unknown[][] }).rows
      const d2Bob = ((await sBob.query('db', { sql: "SELECT id, payload FROM vault_docs WHERE id = 'd2'" })).value as { rows: unknown[][] }).rows
      expect(await sAlice.vaults.unsealRows(d2Alice)).toEqual([['d2', { price: '$3M' }]])
      expect(await sBob.vaults.unsealRows(d2Bob)).toEqual([['d2', null]])

      // Plain text mentioning the vault format marker must NEVER be destroyed by unsealRows(),
      // and { columns, rows } query objects are supported directly!
      const plainText = 'Docs mention "chronolog-vault-box/v1" format safely'
      const unsealedObj = await sAlice.vaults.unsealRows({ columns: ['id', 'note', 'payload'], rows: [['n1', plainText, JSON.stringify(vBox1)]] })
      expect(unsealedObj).toEqual({ columns: ['id', 'note', 'payload'], rows: [['n1', plainText, { price: '$3M' }]] })

      // Verify 16-member X-Wing structural-sharing TreeKEM DAG (>64 KiB if monolithic) + stateless updater self-recovery
      const { bytesToHex } = await import('@chronolog/canonical')
      const { buildTreeEpochUpdate, openTreeEpoch, writeKeyTreeToCas, readKeyTreeFromCas, KEY_TREE_SUITE_XWING } = await import('@chronolog/crypto')
      const { createPqWrapKeyPair } = await import('./wrap-keys.js')
      const bigMembers = Array.from({ length: 16 }, () => {
        const pq = createPqWrapKeyPair()
        return {
          publicKey: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
          wrapKey: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
          pqWrapKey: pq.publicKey,
          pqSecretKey: pq.secretKey,
        }
      })
      const bigTree = await buildTreeEpochUpdate({
        scope: 'big-scope',
        epoch: 1,
        updaterPublicKey: bigMembers[0]!.publicKey,
        activeMembers: bigMembers,
        suite: KEY_TREE_SUITE_XWING,
      })
      const dagStore = new Map<string, Uint8Array>()
      const { computeCasHash } = await import('@chronolog/records')
      const dagRootHash = await writeKeyTreeToCas(bigTree.payload, async (bytes, links) => {
        const h = computeCasHash(bytes, links)
        dagStore.set(h, bytes)
        return h
      })
      expect(dagStore.size).toBeGreaterThan(2)
      const roundTripped = await readKeyTreeFromCas(dagRootHash, async h => dagStore.get(h) ?? null)
      expect(roundTripped.ok).toBe(true)
      if (roundTripped.ok) {
        // Updater (index 0) recovers statelessly via its own self-box with empty cachedNodeSeeds!
        const selfOpen = await openTreeEpoch({
          scope: 'big-scope',
          payload: roundTripped.payload,
          keyCommitment: epochKeyCommitment(bigTree.epochKey),
          wrapPrivateKey: admin.wrapKey.privateKey,
          wrapPublicKeyHex: bigMembers[0]!.wrapKey,
          pqSecretKey: bigMembers[0]!.pqSecretKey,
          pqPublicKeyHex: bigMembers[0]!.pqWrapKey,
        })
        expect(selfOpen).not.toBeNull()
        expect(bytesToHex(selfOpen!.epochKey)).toBe(bytesToHex(bigTree.epochKey))
      }
      // Missing subtree CAS node is reported cleanly
      const someChildHash = [...dagStore.keys()].find(h => h !== dagRootHash)!
      dagStore.delete(someChildHash)
      const missingRes = await readKeyTreeFromCas(dagRootHash, async h => dagStore.get(h) ?? null)
      expect(missingRes.ok).toBe(false)
      if (!missingRes.ok) expect(missingRes.missingHashes).toContain(someChildHash)
    } finally {
      await sAdmin.close()
      await sAlice.close()
      await sBob.close()
      await sAgent.close()
      for (const s of sExtras) await s.close()
    }
  }, 60_000)
})

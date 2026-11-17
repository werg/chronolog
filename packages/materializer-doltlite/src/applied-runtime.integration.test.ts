import { afterEach, describe, expect, it } from 'vitest'
import { join } from 'node:path'
import { APPLICATION_COLLECTIVE_ID, encodeTransactionCore, platformOp, program, sqlStatement, transactionDigest } from '@chronolog/protocol'

import { AppliedMaterializer, DeterministicMaterializer } from './native.js'
import { createDoltLiteExecutionManifest } from './manifest.js'
import { createDoltLiteAppliedMaterializationRuntime } from './runtime-adapter.js'
import { MaterializerFixture, ROOT_KEY, replayProposal, testKey } from './test-fixtures.js'

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())

async function fixture() {
  return {
    path: join(await fixtures.directory(), 'applied.db'),
    executionManifest: createDoltLiteExecutionManifest({ sqlPolicy: 'data-only' }),
    sqlPolicy: 'data-only' as const,
    authorizationPolicy: 'transaction-grants' as const,
    rootAdministrator: ROOT_KEY,
    bootstrapGroupId: testKey(1),
    bootstrapProgram: program(
      sqlStatement('CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL) STRICT'),
      sqlStatement('INSERT INTO accounts (id, balance) VALUES (1, 100)'),
    ),
  }
}

function withdraw(amount: number) {
  return [
    sqlStatement("SELECT chronolog_assert((SELECT balance FROM accounts WHERE id=1) >= ?, 'insufficient')", [amount]),
    sqlStatement('UPDATE accounts SET balance = balance - ? WHERE id=1', [amount]),
  ]
}

describe('finality-free SQL replay', () => {
  it('derives identical historical authority and current rights regardless of control arrival order', async () => {
    const base = await fixture(), other = await fixture()
    const manifest = createDoltLiteExecutionManifest({ sqlPolicy: 'data-only', authorizationPolicy: 'external-membership' })
    const options = { ...base, executionManifest: manifest, authorizationPolicy: 'external-membership' as const }
    const incremental = createDoltLiteAppliedMaterializationRuntime(await AppliedMaterializer.open(options))
    const direct = createDoltLiteAppliedMaterializationRuntime(await AppliedMaterializer.open({ ...options, path: other.path }))
    const controls = [
      { revision: 0, digest: testKey(61), members: [{ publicKey: ROOT_KEY, role: 'member' as const }] },
      { revision: 1, digest: testKey(62), members: [{ publicKey: testKey(2), role: 'member' as const }] },
      { revision: 2, digest: testKey(63), members: [{ publicKey: ROOT_KEY, role: 'admin' as const }, { publicKey: testKey(3), role: 'member' as const }] },
    ]
    for (let index = 0; index < controls.length; index++) {
      await incremental.coordinator.materialize([], { applicationId: base.bootstrapGroupId, currentRevision: index, revisions: controls.slice(0, index + 1) })
    }
    const current = { applicationId: base.bootstrapGroupId, currentRevision: 2, revisions: controls }
    await direct.coordinator.materialize([], current)
    const original = await replayProposal(10n, 'historical-authority', [
      sqlStatement("SELECT chronolog_assert(NOT EXISTS(SELECT 1 FROM chronolog_collective_members WHERE collective_id=? AND member_key=?), 'future_member')",
        [APPLICATION_COLLECTIVE_ID, testKey(2)]),
      sqlStatement('UPDATE accounts SET balance=balance+1 WHERE id=1'),
    ], incremental.queries.executionManifestDigest)
    const core = { ...original.core, membershipRevision: controls[0]!.digest }
    const canonicalCandidate = encodeTransactionCore(core)
    const proposal = { ...original, core, canonicalCandidate, candidateDigest: await transactionDigest(canonicalCandidate) }
    const contentHashes: string[] = []
    for (const runtime of [incremental, direct]) {
      contentHashes.push((await runtime.coordinator.materialize([proposal], current))!.revision.contentHash)
      expect(runtime.queries.outcome(proposal.txId)?.outcome).toBe('accepted')
    }
    expect(contentHashes[0]).toBe(contentHashes[1])
    const parameters = [{ kind: 'blob' as const, value: APPLICATION_COLLECTIVE_ID }]
    for (const sql of [
      'SELECT created_tx FROM chronolog_collectives WHERE collective_id=?',
      'SELECT member_key,role,state,joined_tx,left_tx FROM chronolog_collective_members WHERE collective_id=? ORDER BY member_key',
    ]) expect(incremental.queries.localSql(sql, parameters).rows).toEqual(direct.queries.localSql(sql, parameters).rows)
    expect(incremental.queries.localSql('SELECT id,key FROM chronolog_principals ORDER BY id').rows)
      .toEqual(direct.queries.localSql('SELECT id,key FROM chronolog_principals ORDER BY id').rows)
    await incremental.close(); await direct.close()
  })

  it('requires authenticated external membership and never restores older authority with an application rollback', async () => {
    const options = { ...await fixture(), authorizationPolicy: 'external-membership' as const,
      executionManifest: createDoltLiteExecutionManifest({ sqlPolicy: 'data-only', authorizationPolicy: 'external-membership' }) }
    expect(() => createDoltLiteExecutionManifest({ sqlPolicy: 'authorized', authorizationPolicy: 'external-membership' }))
      .toThrow('MATERIALIZER_EXTERNAL_MEMBERSHIP_REQUIRES_DATA_ONLY')
    await expect(DeterministicMaterializer.open(options)).rejects.toThrow('MATERIALIZER_EXTERNAL_AUTHORIZATION_REQUIRES_APPLIED_RUNTIME')
    const runtime = createDoltLiteAppliedMaterializationRuntime(await AppliedMaterializer.open(options))
    await expect(runtime.coordinator.materialize([])).rejects.toThrow('MATERIALIZER_PEER_CONTROLS_REQUIRED')
    const first = { revision: 0, digest: testKey(61), members: [{ publicKey: ROOT_KEY, role: 'member' as const }] }
    const original = { applicationId: options.bootstrapGroupId, currentRevision: 0, revisions: [first] }
    await runtime.coordinator.materialize([], original)
    const held = runtime.queries.captureRead()
    const latest = { applicationId: options.bootstrapGroupId, currentRevision: 1,
      revisions: [first, { revision: 1, digest: testKey(62), members: [{ publicKey: testKey(2), role: 'member' as const }] }] }
    await runtime.coordinator.materialize([], latest)
    expect(runtime.queries.revision).toBe(2n)
    const sql = 'SELECT state FROM chronolog_collective_members WHERE member_key = ? AND collective_id = ?'
    const key = [{ kind: 'blob' as const, value: ROOT_KEY }, { kind: 'blob' as const, value: APPLICATION_COLLECTIVE_ID }]
    expect(held.query(sql, key).rows).toEqual([[{ kind: 'text', value: 'active' }]])
    expect(runtime.queries.localSql(sql, key).rows).toEqual([[{ kind: 'text', value: 'left' }]])
    await expect(runtime.coordinator.materialize([], original)).rejects.toThrow('MATERIALIZER_PEER_CONTROL_REGRESSION')
    held.release()
    await runtime.close()
    const reopened = createDoltLiteAppliedMaterializationRuntime(await AppliedMaterializer.open(options))
    await expect(reopened.coordinator.materialize([], original)).rejects.toThrow('MATERIALIZER_PEER_CONTROL_REGRESSION')
    await expect(reopened.coordinator.materialize([], latest)).resolves.toBeNull()
    expect(reopened.queries.localSql(sql, key).rows).toEqual([[{ kind: 'text', value: 'left' }]])
    await reopened.close()
  })

  it('publishes restored content as a new revision while preserving exact retry identity', async () => {
    const runtime = createDoltLiteAppliedMaterializationRuntime(await AppliedMaterializer.open(await fixture()))
    const late = await replayProposal(20n, 'late', withdraw(80), runtime.queries.executionManifestDigest)
    const early = await replayProposal(10n, 'early', withdraw(60), runtime.queries.executionManifestDigest)
    const first = (await runtime.coordinator.materialize([late]))!
    const firstResult = await runtime.publications.publish(first.publication)
    const middle = (await runtime.coordinator.materialize([early, late]))!
    await runtime.publications.publish(middle.publication)
    const restored = (await runtime.coordinator.materialize([late]))!
    expect(restored.revision.contentHash).toBe(first.revision.contentHash)
    expect(restored.publication.publicationKey).not.toBe(first.publication.publicationKey)
    const restoredResult = await runtime.publications.publish(restored.publication)
    expect(restoredResult.revision).toBe(3n)
    expect(await runtime.publications.publish(restored.publication)).toEqual(restoredResult)
    expect(await runtime.publications.publish(first.publication)).toEqual(firstResult)
    await expect(runtime.publications.publish({ ...restored.publication, candidateIdentity: 'different-content' }))
      .rejects.toThrow('MATERIALIZATION_PUBLICATION_KEY_REUSED')
    expect(runtime.queries.revision).toBe(3n)
    expect(runtime.queries.outcome(late.txId)?.outcome).toBe('accepted')
    await runtime.close()
  })

  it('replays earlier intent with coherent applied snapshots and no final view or prefix', async () => {
    const options = await fixture()
    const engine = await AppliedMaterializer.open(options)
    const runtime = createDoltLiteAppliedMaterializationRuntime(engine)
    expect(engine).not.toHaveProperty('publishFinal')
    expect(engine).not.toHaveProperty('finalOrderLength')
    expect(runtime.coordinator).not.toHaveProperty('publishFinal')
    expect(runtime.queries).not.toHaveProperty('finalRevision')
    const late = await replayProposal(20n, 'late', withdraw(80), runtime.queries.executionManifestDigest)
    const early = await replayProposal(10n, 'early', withdraw(60), runtime.queries.executionManifestDigest)
    const first = await runtime.coordinator.materialize([late])
    await runtime.publications.publish(first!.publication)
    const held = runtime.queries.captureRead()
    const oldRows = held.query('SELECT balance FROM accounts').rows
    expect(oldRows).toEqual([[{ kind: 'integer', value: '20' }]])
    expect(held).not.toHaveProperty('view')
    expect(held).not.toHaveProperty('finalOrderLength')
    expect(held.query('SELECT balance FROM accounts')).not.toHaveProperty('finalOrderLength')
    expect(held.transactionAt(0)?.outcome).toBe('accepted')
    await runtime.coordinator.materialize([early, late])
    expect(runtime.queries.outcome(late.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'assert:insufficient' })
    expect(runtime.queries.localSql('SELECT balance FROM accounts').rows).toEqual([[{ kind: 'integer', value: '40' }]])
    expect(held.query('SELECT balance FROM accounts').rows).toEqual(oldRows)
    expect(held.transactionAt(0)?.outcome).toBe('accepted')
    const current = runtime.queries.captureApplication()
    expect(current.transactionAt(0)?.txId).toEqual(early.txId)
    expect(current.transactionAt(1)?.outcome).toBe('rejected')
    await expect(runtime.coordinator.materialize([late, early])).rejects.toThrow('ORDER_NOT_CHRONOLOGICAL')
    held.release()
    await runtime.close()

    const reopened = createDoltLiteAppliedMaterializationRuntime(await AppliedMaterializer.open(options))
    expect(reopened.queries.outcome(late.txId)?.outcome).toBe('rejected')
    await reopened.coordinator.materialize([late])
    expect(reopened.queries.outcome(late.txId)?.outcome).toBe('accepted')
    expect(reopened.queries.localSql('SELECT balance FROM accounts').rows).toEqual(oldRows)
    await reopened.close()
  })

  it('authenticates SQL authority semantics and rejects different retained genesis or publication bindings', async () => {
    const options = await fixture()
    const authorized = createDoltLiteExecutionManifest({ sqlPolicy: 'authorized' })
    expect(options.executionManifest.platformDigest).not.toEqual(authorized.platformDigest)
    const runtime = createDoltLiteAppliedMaterializationRuntime(await AppliedMaterializer.open(options))
    const forbiddenSchema = await replayProposal(1n, 'ddl', ['CREATE TABLE forbidden (id INTEGER PRIMARY KEY)'], runtime.queries.executionManifestDigest)
    const forbiddenRights = await replayProposal(2n, 'rights', [platformOp.grant({ table: 'accounts', grantee: testKey(2), operations: ['update'] })], runtime.queries.executionManifestDigest)
    await runtime.coordinator.materialize([forbiddenSchema, forbiddenRights])
    expect(runtime.queries.outcome(forbiddenSchema.txId)?.outcome).toBe('rejected')
    expect(runtime.queries.outcome(forbiddenRights.txId)?.rejectionCode).toBe('protected_change_required')
    await runtime.close()
    await expect(AppliedMaterializer.open({ ...options, sqlPolicy: 'authorized' })).rejects.toThrow('PLATFORM_DIGEST_MISMATCH')
    await expect(AppliedMaterializer.open({ ...options, sqlPolicy: 'authorized', executionManifest: authorized })).rejects.toThrow('MANIFEST')
    await expect(AppliedMaterializer.open({ ...options, bootstrapProgram: program('CREATE TABLE replacement (id INTEGER PRIMARY KEY)') }))
      .rejects.toThrow('DATABASE_BOOTSTRAP_MISMATCH')
    await expect(AppliedMaterializer.open({ ...options, bootstrapGroupId: testKey(2) })).rejects.toThrow('DATABASE_BOOTSTRAP_MISMATCH')
    await expect(DeterministicMaterializer.open(options)).rejects.toThrow('DATABASE_PUBLICATION_MODE_MISMATCH')
    const reopened = await AppliedMaterializer.open(options)
    expect(reopened.orderLength).toBe(2)
    reopened.close()
  })

  it('keeps applied SQL and event outcomes at the previous revision when publication fails', async () => {
    const options = await fixture()
    let fail = false
    const runtime = createDoltLiteAppliedMaterializationRuntime(await AppliedMaterializer.open({ ...options,
      publicationFaultInjector(point) { if (fail && point === 'before_head_publish') throw new Error('publication unavailable') },
    }))
    const late = await replayProposal(20n, 'late', withdraw(80), runtime.queries.executionManifestDigest)
    const early = await replayProposal(10n, 'early', withdraw(60), runtime.queries.executionManifestDigest)
    await runtime.coordinator.materialize([late])
    const previous = runtime.queries.captureApplication()
    fail = true
    await expect(runtime.coordinator.materialize([early, late])).rejects.toThrow('publication unavailable')
    expect(runtime.queries.revision).toBe(previous.revision)
    expect(runtime.queries.captureApplication().transactionAt(0)).toEqual(previous.transactionAt(0))
    expect(runtime.queries.localSql('SELECT balance FROM accounts').rows).toEqual([[{ kind: 'integer', value: '20' }]])
    fail = false
    await runtime.coordinator.materialize([early, late])
    expect(runtime.queries.captureApplication().transactionAt(1)?.outcome).toBe('rejected')
    await runtime.close()
  })
})

import { afterEach, describe, expect, it } from 'vitest'
import { join } from 'node:path'
import { platformOp, program, sqlStatement } from '@chronolog/protocol'

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

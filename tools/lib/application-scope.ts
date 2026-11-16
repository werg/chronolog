import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { decodeEnvelope, type ChangeProgram, type EventPayload } from '@chronolog/protocol'
import { createChronologApplicationBackend } from '@chronolog/transport-tendriller'
import type { ApplicationOperation } from '@tendriller/core/application'

import { createNativeBrowserFixture } from '../browser-event-fixture.js'

interface ScopePrograms {
  initializeScopedState(input: { scope: string; value?: EventPayload }): ChangeProgram
  setScopedState(input: { scope: string; expectedGeneration: number; value: EventPayload }): ChangeProgram
  rotateScopedState(input: { scope: string; expectedGeneration: number; value?: EventPayload }): ChangeProgram
}

/** Exercise the exact built contrib recipe through the public native application adapter. */
export async function qualifyApplicationScope(modulePath: string) {
  const recipe = await import(pathToFileURL(modulePath).href) as ScopePrograms
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-scope-qualification-'))
  const executionManifest = createDoltLiteExecutionManifest()
  const native = await createNativeBrowserFixture({ directory, browsers: [], manifest: executionManifest,
    materialization: async ({ identity }) => createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open({
      path: join(directory, 'application.db'), executionManifest, rootAdministrator: identity.signing.publicKeyBytes,
    })) })
  try {
    // Stop automatic ordering, retaining the same fenced native authority. This
    // lets an already durable authored edit arrive after a separately authored reset.
    await native.agent.close()
    const authority = native.agent.authority
    assert(authority !== null)
    // Complete the retained genesis key controls before choosing application order.
    for (const record of await native.transport.history()) {
      const kind = decodeEnvelope(record.payload).messageType
      if (kind === 'capability' || kind === 'epoch-manifest') await authority.append(record.payload)
    }
    await authority.share({ putEvidence: bytes => native.transport.putEvidence(bytes) })
    const backend = createChronologApplicationBackend({ id: 'scope-qualification', replica: native.client, sql: true })
    const submit = async (change: ChangeProgram, operationId: string) => {
      const before = (await native.transport.history()).length
      const receipt = await backend.submit(change, { operationId })
      const appended = (await native.transport.history()).slice(before)
      assert.equal(appended.length, 1, 'One durable authored record per new operation')
      return { receipt, record: appended[0]! }
    }
    const order = async (pending: Awaited<ReturnType<typeof submit>>): Promise<ApplicationOperation> => {
      await authority.append(pending.record.payload)
      await authority.share({ putEvidence: bytes => native.transport.putEvidence(bytes) })
      for await (const value of backend.operations.subscribe({ operationId: pending.receipt.operationId, signal: AbortSignal.timeout(10_000) })) {
        if (value.status === 'final' || value.status === 'rejected') return value
      }
      throw new Error('SCOPE_OPERATION_DID_NOT_SETTLE')
    }
    const scope = 'inspection-notes'
    assert.equal((await order(await submit(recipe.initializeScopedState({ scope }), 'scope-initialize'))).status, 'final')
    const original = recipe.setScopedState({ scope, expectedGeneration: 0, value: { note: 'already accepted' } })
    const accepted = await order(await submit(original, 'scope-accepted'))
    assert.equal(accepted.status, 'final')
    const stale = await submit(recipe.setScopedState({ scope, expectedGeneration: 0, value: { note: 'offline edit' } }), 'scope-stale')
    assert.notEqual((await backend.operations.get('scope-stale'))?.status, 'final')
    const reset = await order(await submit(recipe.rotateScopedState({ scope, expectedGeneration: 0, value: { note: 'reset' } }), 'scope-reset'))
    assert.equal(reset.status, 'final')
    const rejection = await order(stale)
    assert.equal(rejection.status, 'rejected')
    assert.equal(rejection.error, 'assert:scope_generation_changed')
    assert.equal(rejection.proposalId, stale.receipt.proposalId)

    const beforeRetry = await native.transport.history()
    const retried = await backend.submit(original, { operationId: 'scope-accepted' })
    assert.equal(retried.proposalId, accepted.proposalId)
    assert.deepEqual(await backend.operations.get('scope-accepted'), accepted)
    await assert.rejects(backend.submit(recipe.setScopedState({ scope, expectedGeneration: 1, value: { note: 'rewritten retry' } }),
      { operationId: 'scope-accepted' }), { code: 'already_exists' })
    assert.deepEqual(await native.transport.history(), beforeRetry)
    const view = await backend.readView({ view: 'final' })
    try {
      const rows = await view.query('SELECT generation, value_json FROM app_scoped_state WHERE scope = ?', [scope])
      assert.equal(rows.truncated, false)
      assert.deepEqual(rows.rows, [[1n, '{"note":"reset"}']])
      const events = (await view.readEvents({ topics: ['scoped-state'] })).transactions.flatMap(transaction => transaction.events)
      assert.equal(events.length, 3)
      assert(!events.some(event => event.proposalId === stale.receipt.proposalId))
      native.assertHealthy()
      return { acceptedProposalId: accepted.proposalId, staleProposalId: rejection.proposalId, resetProposalId: reset.proposalId,
        generation: 1, effectiveEvents: events.length, rejectedCode: rejection.error, exactRetryAddsRecords: 0 }
    } finally { await view.release() }
  } finally {
    await native.close()
    await rm(directory, { recursive: true, force: true })
  }
}

import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { decodeFinalityClosureRecord, isFinalityClosureRecord } from '@chronolog/node-core/finality'
import { assertCanonicalCbor, decodeEnvelope, utf8, type ChangeProgram, type EventPayload } from '@chronolog/protocol'
import { createChronologApplicationBackend } from '@chronolog/transport-tendriller'
import type { ApplicationOperation } from '@tendriller/core/application'

import { createNativeBrowserFixture } from '../browser-event-fixture.js'
import { createFinalityEvidencePublisher } from './finality-evidence.js'

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
  let materializer: DeterministicMaterializer | undefined
  const native = await createNativeBrowserFixture({ directory, browsers: [], manifest: executionManifest,
    materialization: async ({ identity }) => {
      materializer = await DeterministicMaterializer.open({ path: join(directory, 'application.db'),
        executionManifest, rootAdministrator: identity.signing.publicKeyBytes })
      return createDoltLiteMaterializationRuntime(materializer)
    } })
  try {
    // Pause automatic inclusion/closure, retaining the same fenced service.
    // This lets an original offline edit arrive after the reset's time closes.
    await native.agent.close()
    const authority = native.agent.finality
    assert(authority !== null)
    const publishEvidence = createFinalityEvidencePublisher(authority, { putEvidence: bytes => native.transport.putEvidence(bytes) })
    // Finalize the retained genesis key controls before submitting application work.
    for (const record of await native.transport.history()) {
      const kind = decodeEnvelope(record.payload).messageType
      if (kind === 'capability' || kind === 'epoch-manifest') await authority.append(record.payload)
    }
    await publishEvidence()
    const backend = createChronologApplicationBackend({ id: 'scope-qualification', replica: native.client, sql: true })
    const submit = async (change: ChangeProgram, operationId: string) => {
      const before = (await native.transport.history()).length
      const receipt = await backend.submit(change, { operationId })
      const appended = (await native.transport.history()).slice(before)
      assert.equal(appended.length, 1, 'One durable authored record per new operation')
      return { receipt, record: appended[0]! }
    }
    const include = async (pending: Awaited<ReturnType<typeof submit>>): Promise<ApplicationOperation> => {
      await authority.append(pending.record.payload)
      const started = performance.now()
      const deadline = Date.now() + 10_000
      let attempts = 0
      while (Date.now() < deadline) {
        attempts++
        await publishEvidence()
        await native.node.waitForIdle()
        const value = await backend.operations.get(pending.receipt.operationId)
        if (value?.status === 'final') return value
        await new Promise(resolve => setTimeout(resolve, 10))
      }
      const txId = utf8(pending.receipt.proposalId)
      const [operation, status, range] = await Promise.all([
        backend.operations.get(pending.receipt.operationId), native.node.status(), authority.read({ limit: 256 }),
      ])
      const closure = range.entries.filter(entry => isFinalityClosureRecord(entry.bytes))
        .map(entry => decodeFinalityClosureRecord(entry.bytes)).at(-1)
      const applied = assertCanonicalCbor(await native.node.finalTarget())
      const candidate = native.node.candidate(txId)
      const diagnostic = { operationId: pending.receipt.operationId, operation, attempts, elapsedMs: Math.round(performance.now() - started),
        candidate: candidate === null ? null : { state: candidate.state, reason: candidate.stateReason,
          authorTimestampMs: candidate.orderKey.authorTimestampMs },
        outcome: native.node.outcome(txId), materializerOutcome: materializer?.outcome(txId), status,
        finality: { head: range.head, hasMore: range.hasMore, closedThroughMs: closure?.closedThroughMs,
          closedReceiptThrough: closure?.includedHead.position, appliedThrough: native.node.finalThrough,
          appliedClosedThroughMs: Array.isArray(applied) && typeof applied[6] === 'bigint' ? applied[6] : null } }
      throw new Error(`SCOPE_OPERATION_DID_NOT_SETTLE:${JSON.stringify(diagnostic, (_key, value: unknown) =>
        typeof value === 'bigint' ? value.toString() : value)}`)
    }
    const scope = 'inspection-notes'
    assert.equal((await include(await submit(recipe.initializeScopedState({ scope }), 'scope-initialize'))).outcome, 'accepted')
    const original = recipe.setScopedState({ scope, expectedGeneration: 0, value: { note: 'already accepted' } })
    const accepted = await include(await submit(original, 'scope-accepted'))
    assert.equal(accepted.outcome, 'accepted')
    const stale = await submit(recipe.setScopedState({ scope, expectedGeneration: 0, value: { note: 'offline edit' } }), 'scope-stale')
    assert.notEqual((await backend.operations.get('scope-stale'))?.status, 'final')
    const reset = await include(await submit(recipe.rotateScopedState({ scope, expectedGeneration: 0, value: { note: 'reset' } }), 'scope-reset'))
    assert.equal(reset.outcome, 'accepted')
    const rejection = await include(stale)
    assert.equal(rejection.status, 'final')
    assert.equal(rejection.outcome, 'rejected')
    assert.equal(rejection.error, 'FINALITY_TIMESTAMP_CLOSED')
    assert.equal(rejection.proposalId, stale.receipt.proposalId)
    // A newly authored edit carrying the captured old generation reaches SQL
    // in chronological order and is independently rejected by the application guard.
    const generationRejection = await include(await submit(recipe.setScopedState({ scope,
      expectedGeneration: 0, value: { note: 'stale captured generation' } }), 'scope-stale-generation'))
    assert.equal(generationRejection.status, 'final')
    assert.equal(generationRejection.outcome, 'rejected')
    assert.equal(generationRejection.error, 'assert:scope_generation_changed')

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
        generation: 1, effectiveEvents: events.length, rejectedCode: generationRejection.error,
        closedRejectionCode: rejection.error, generationRejectedProposalId: generationRejection.proposalId,
        exactRetryAddsRecords: 0 }
    } finally { await view.release() }
  } finally {
    await native.close()
    await rm(directory, { recursive: true, force: true })
  }
}

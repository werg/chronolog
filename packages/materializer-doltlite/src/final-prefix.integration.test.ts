import { afterEach, describe, expect, it } from 'vitest'

import { FINAL_BRANCH, HEAD_BRANCH } from './checkpoints.js'
import { openDatabase } from './driver.js'
import { DeterministicMaterializer } from './materializer.js'
import { createNativeSqlEngine } from './native.js'
import { MaterializerFixture, ROOT_KEY, replayProposal } from './test-fixtures.js'
import type { DatabaseLike, ReplayProposal } from './types.js'

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())

describe('incremental immutable final SQL prefixes', () => {
  it('executes only the newly settled suffix across increments and reopen, with the same content as one-shot finalization', async () => {
    const incremental = await instrumented(100)
    let materializer = await incremental.open()
    const history = await proposals(materializer.executionManifestDigest)
    await materializer.materialize(history)
    incremental.executions.length = 0
    await materializer.publishFinal(1)
    const held = materializer.captureRead({ view: 'final' })
    try {
      await materializer.publishFinal(2)
      await materializer.publishFinal(3)
      expect(incremental.executions).toEqual(['schema', 'first', 'duplicate'])
      expect(materializer.captureApplication({ view: 'final' }).transactionAt(2)?.outcome).toBe('rejected')
      expect(held.orderLength).toBe(1)
      expect(held.query('SELECT count(*) FROM final_rows').rows).toEqual([[{ kind: 'integer', value: '0' }]])
    } finally { held.release(); materializer.close() }

    materializer = await incremental.open()
    try {
      await materializer.publishFinal(4)
      expect(incremental.executions).toEqual(['schema', 'first', 'duplicate', 'second'])
      expect(materializer.finalRevision).toBe(4n)
      expect(materializer.localSql('SELECT id FROM final_rows ORDER BY id', [], { view: 'final' }).rows)
        .toEqual([[{ kind: 'integer', value: '1' }], [{ kind: 'integer', value: '2' }]])

      const oneShot = await instrumented(100)
      const reference = await oneShot.open()
      try {
        await reference.materialize(history)
        await reference.publishFinal(4)
        const actual = materializer.captureApplication({ view: 'final' })
        const expected = reference.captureApplication({ view: 'final' })
        expect(actual.orderLength).toBe(expected.orderLength)
        expect(Array.from({ length: actual.orderLength }, (_, index) => actual.transactionAt(index)))
          .toEqual(Array.from({ length: expected.orderLength }, (_, index) => expected.transactionAt(index)))
        expect(incremental.writer().doltHashOf(FINAL_BRANCH)).toBe(oneShot.writer().doltHashOf(FINAL_BRANCH))
      } finally { reference.close() }
    } finally { materializer.close() }
  })

  it('uses a nearer ordinary checkpoint instead of an older immutable final prefix', async () => {
    const fixture = await instrumented(3)
    const materializer = await fixture.open()
    try {
      const history = await proposals(materializer.executionManifestDigest)
      await materializer.materialize(history.slice(0, 3))
      await materializer.materialize(history)
      await materializer.publishFinal(1)
      expect(materializer.checkpoints().map(checkpoint => checkpoint.prefixLength)).toEqual([0, 3])
      fixture.executions.length = 0
      await materializer.publishFinal(4)
      expect(fixture.executions).toEqual(['second'])
      expect(materializer.finalOrderLength).toBe(4)
      expect(materializer.captureApplication({ view: 'final' }).transactionAt(2)?.outcome).toBe('rejected')
    } finally { materializer.close() }
  })

  it.each(['commit', 'reader-validation'] as const)('discards unpublished final replay after %s failure and retries from the prior immutable base', async (fault) => {
    const fixture = await instrumented(100)
    let materializer = await fixture.open()
    const history = await proposals(materializer.executionManifestDigest)
    await materializer.materialize(history)
    await materializer.publishFinal(1)
    const before = materializer.captureApplication({ view: 'final' })
    const held = materializer.captureRead({ view: 'final' })
    const localHash = materializer.databaseContentHash
    const finalHash = fixture.writer().doltHashOf(FINAL_BRANCH)
    const workingBeforeFailure = fixture.writer().prepare('SELECT * FROM dolt_status').all()
    fixture.executions.length = 0
    fixture.fail(fault)
    try {
      await expect(materializer.publishFinal(3)).rejects.toThrow(`FINAL_REPLAY_${fault}`)
      expect(materializer.finalRevision).toBe(before.revision)
      expect(materializer.finalOrderLength).toBe(before.orderLength)
      expect(fixture.writer().doltHashOf(FINAL_BRANCH)).toBe(finalHash)
      expect(materializer.databaseContentHash).toBe(localHash)
      expect(fixture.writer().doltActiveBranch()).toBe(HEAD_BRANCH)
      expect(fixture.writer().doltBranches().filter(branch => branch.name.startsWith('chronolog_replay_'))).toEqual([])
      expect(fixture.writer().prepare('SELECT * FROM dolt_status').all()).toEqual(workingBeforeFailure)
      expect(held.query('SELECT count(*) FROM final_rows').rows).toEqual([[{ kind: 'integer', value: '0' }]])
      expect(materializer.localSql('SELECT count(*) FROM final_rows', [], { view: 'local' }).rows).toEqual([[{ kind: 'integer', value: '3' }]])
      await materializer.publishFinal(3)
      expect(fixture.executions).toEqual(['first', 'duplicate', 'first', 'duplicate'])
      expect(materializer.finalOrderLength).toBe(3)
      expect(materializer.captureApplication({ view: 'final' }).transactionAt(2)?.outcome).toBe('rejected')
    } finally { held.release(); materializer.close() }
    materializer = await fixture.open()
    try {
      expect(materializer.finalOrderLength).toBe(3)
      expect(materializer.localSql('SELECT count(*) FROM final_rows', [], { view: 'final' }).rows)
        .toEqual([[{ kind: 'integer', value: '1' }]])
    } finally { materializer.close() }
  })
})

async function proposals(digest: Uint8Array): Promise<readonly ReplayProposal[]> {
  return Promise.all([
    replayProposal(1n, 'schema', ['CREATE TABLE final_rows (id INTEGER PRIMARY KEY)'], digest),
    replayProposal(2n, 'first', ['INSERT INTO final_rows (id) VALUES (1)'], digest),
    replayProposal(3n, 'duplicate', ['INSERT INTO final_rows (id) VALUES (1)'], digest),
    replayProposal(4n, 'second', ['INSERT INTO final_rows (id) VALUES (2)'], digest),
    replayProposal(5n, 'tentative', ['INSERT INTO final_rows (id) VALUES (3)'], digest),
  ])
}

async function instrumented(checkpointEvery: number) {
  const path = `${await fixtures.directory()}/application.db`
  const manifest = createNativeSqlEngine().executionManifest
  const executions: string[] = []
  let writer: DatabaseLike | undefined
  let fault: 'commit' | 'reader-validation' | undefined
  return {
    executions,
    writer: () => { if (writer === undefined) throw new Error('TEST_WRITER_NOT_OPEN'); return writer },
    fail: (value: typeof fault) => { fault = value },
    open: () => {
      let openedCount = 0
      return DeterministicMaterializer.open({ path, engine: { executionManifest: manifest, openDatabase(options) {
          const opened = openDatabase(options)
          const native = opened.database
          const isWriter = openedCount++ === 0
          const database: DatabaseLike = {
            get inTransaction() { return native.inTransaction },
            exec: native.exec.bind(native), close: native.close.bind(native),
            triggerUsesIgnore: native.triggerUsesIgnore.bind(native), configureSecurity: native.configureSecurity.bind(native),
            setAuthorizer: native.setAuthorizer.bind(native), setProgressHandler: native.setProgressHandler.bind(native),
            setLimit: native.setLimit.bind(native), interrupt: native.interrupt.bind(native),
            clearDeterministicContext: native.clearDeterministicContext.bind(native),
            doltBranch: native.doltBranch.bind(native), doltCheckout: native.doltCheckout.bind(native),
            doltResetHard: native.doltResetHard.bind(native), doltForceBranch: native.doltForceBranch.bind(native),
            doltDeleteBranch: native.doltDeleteBranch.bind(native), doltHashOf: native.doltHashOf.bind(native),
            doltVersion: native.doltVersion.bind(native), doltBranches: native.doltBranches.bind(native),
            doltActiveBranch: native.doltActiveBranch.bind(native),
            setDeterministicContext(timestamp, seed, actor, actorId, transactionId) {
              if (transactionId !== undefined && transactionId !== null) executions.push(new TextDecoder().decode(transactionId))
              native.setDeterministicContext(timestamp, seed, actor, actorId, transactionId)
            },
            doltCommit(message) {
              if (fault === 'commit' && message.startsWith('chronolog final prefix')) {
                fault = undefined
                throw new Error('FINAL_REPLAY_commit')
              }
              return native.doltCommit(message)
            },
            prepare(sql) {
              if (!isWriter && fault === 'reader-validation' && sql.includes('SELECT manifest_digest, canonical_manifest, bootstrap_program') &&
                  native.doltActiveBranch().startsWith('chronolog_read_')) {
                fault = undefined
                throw new Error('FINAL_REPLAY_reader-validation')
              }
              return native.prepare(sql)
            },
          }
          if (isWriter) writer = database
          return { ...opened, database }
        } }, rootAdministrator: ROOT_KEY, checkpointEvery,
      })
    },
  }
}

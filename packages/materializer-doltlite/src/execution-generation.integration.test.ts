import { afterEach, describe, expect, it } from 'vitest'
import { bytesToHex, program } from '@chronolog/protocol'
import type { PeerExecutionControls } from '@chronolog/materializer'
import { createNativeSqlEngine } from './native.js'
import { DeterministicMaterializer } from './materializer.js'
import { MaterializerFixture, ROOT_KEY, replayProposal, rows, testKey } from './test-fixtures.js'
import type { ReplayProposal } from './types.js'

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())
const currentGeneration = `(SELECT lower(hex(generation)) FROM chronolog_execution_context WHERE singleton = 1 AND transaction_id = chronolog_transaction_id())`
const generationA = testKey(41), generationB = testKey(42)

async function fixture() {
  const directory = await fixtures.directory(), engine = createNativeSqlEngine()
  const materializer = await DeterministicMaterializer.open({ path: directory + '/generation.db', engine, rootAdministrator: ROOT_KEY,
    bootstrapGroupId: testKey(1), bootstrapProgram: program(
      `CREATE TABLE work (id TEXT PRIMARY KEY NOT NULL, generation TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('claimed', 'done')))`,
      `CREATE TRIGGER work_insert BEFORE INSERT ON work BEGIN
        SELECT chronolog_assert(NEW.generation IS ${currentGeneration} AND NEW.state = 'claimed', 'generation_mismatch'); END`,
      `CREATE TRIGGER work_update BEFORE UPDATE ON work BEGIN
        SELECT chronolog_assert(NEW.generation IS ${currentGeneration}, 'generation_mismatch');
        SELECT chronolog_assert(NEW.state <> 'done' OR OLD.generation IS ${currentGeneration}, 'claim_needs_rebind'); END`,
    ), checkpointEvery: 1,
  })
  const transactions: ReplayProposal[] = [], generations: NonNullable<PeerExecutionControls['attemptGenerations']>[number][] = []
  const controls = (): PeerExecutionControls => ({ applicationId: testKey(1), currentRevision: 0,
    revisions: [{ revision: 0, digest: testKey(2), members: [{ publicKey: ROOT_KEY, role: 'admin' }] }], attemptGenerations: generations })
  const append = async (sql: string, generation: Uint8Array) => {
    const number = transactions.length + 1
    const proposal = { ...await replayProposal(BigInt(number), 'operation-' + number, [sql], materializer.executionManifestDigest), txId: testKey(80 + number) }
    transactions.push(proposal); generations.push({ attemptId: proposal.txId, generation })
    await materializer.materialize(transactions, controls())
    return materializer.outcome(proposal.txId)
  }
  return { materializer, append, transactions, generations, controls }
}

describe('authenticated SQL execution generation', () => {
  it('fences raw writes after recovery until an explicit current-generation rebind', async () => {
    const f = await fixture()
    try {
      expect(await f.append(`INSERT INTO work VALUES ('slot', '${bytesToHex(generationA)}', 'claimed', chronolog_actor_id())`, generationA)).toMatchObject({ outcome: 'accepted' })
      expect(await f.append(`UPDATE work SET state='done' WHERE id='slot'`, generationB)).toMatchObject({ outcome: 'rejected', rejectionCode: 'assert:generation_mismatch' })
      expect(await f.append(`UPDATE work SET generation='${bytesToHex(generationB)}', state='done' WHERE id='slot'`, generationB)).toMatchObject({ outcome: 'rejected', rejectionCode: 'assert:claim_needs_rebind' })
      expect(await f.append(`UPDATE work SET generation='${bytesToHex(generationB)}' WHERE id='slot'`, generationB)).toMatchObject({ outcome: 'accepted' })
      expect(await f.append(`UPDATE work SET state='done' WHERE id='slot'`, generationB)).toMatchObject({ outcome: 'accepted' })
      expect(rows(f.materializer, 'SELECT generation,state FROM work')).toEqual([[bytesToHex(generationB), 'done']])
      expect(rows(f.materializer, 'SELECT count(*) FROM chronolog_execution_context')).toEqual([['0']])
      // Rewind and replay the original claim under its original authenticated generation.
      await f.materializer.materialize(f.transactions.slice(0, 1), { ...f.controls(), attemptGenerations: f.generations.slice(0, 1) })
      expect(rows(f.materializer, 'SELECT generation,state FROM work')).toEqual([[bytesToHex(generationA), 'claimed']])
      await f.materializer.materialize(f.transactions, f.controls())
      expect(rows(f.materializer, 'SELECT generation,state FROM work')).toEqual([[bytesToHex(generationB), 'done']])
    } finally { f.materializer.close() }
  })

  it('denies raw mutation of context, generation evidence and guards, even for the data administrator', async () => {
    const f = await fixture()
    try {
      expect(await f.append(`DELETE FROM chronolog_execution_context`, generationA)).toMatchObject({ outcome: 'rejected', rejectionCode: 'denied' })
      expect(await f.append(`UPDATE chronolog_execution_context SET generation=X'${bytesToHex(generationB)}'`, generationA)).toMatchObject({ outcome: 'rejected', rejectionCode: 'denied' })
      expect(await f.append(`DELETE FROM chronolog_attempt_generations`, generationA)).toMatchObject({ outcome: 'rejected', rejectionCode: 'denied' })
      expect(await f.append(`DROP TRIGGER work_insert`, generationA)).toMatchObject({ outcome: 'rejected', rejectionCode: 'denied' })
      expect(await f.append(`INSERT INTO work VALUES ('forged', '${bytesToHex(generationB)}', 'claimed', chronolog_actor_id())`, generationA)).toMatchObject({ outcome: 'rejected', rejectionCode: 'assert:generation_mismatch' })
      expect(rows(f.materializer, 'SELECT count(*) FROM work')).toEqual([['0']])
      await expect(f.materializer.materialize(f.transactions, { ...f.controls(), attemptGenerations: [] })).rejects.toThrow('MATERIALIZER_PEER_GENERATION_MISSING')
      const changed = f.generations.map((entry, index) => index === 0 ? { ...entry, generation: generationB } : entry)
      await expect(f.materializer.materialize(f.transactions, { ...f.controls(), attemptGenerations: changed })).rejects.toThrow('MATERIALIZER_PEER_GENERATION_CONFLICT')
    } finally { f.materializer.close() }
  })
})

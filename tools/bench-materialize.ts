/**
 * Materializer CPU cost of owner-checked writes, without feeds or admission.
 *
 *   TXS=300 ROWS=20 pnpm exec tsx tools/bench-materialize.ts
 *
 * Three phases, each materialized as one appended batch of TXS transactions
 * by a writer that is not the initial namespace owner: each transaction inserts,
 * then updates, then deletes ROWS rows it owns. Reports process CPU ms per
 * phase (wall time on a loaded machine is mostly fsync noise).
 */

import type { ReplayProposal } from '@chronolog/materializer-doltlite'
import { MaterializerFixture, replayProposal, testKey } from '@chronolog/materializer-doltlite/testing'

const TXS = Number(process.env.TXS ?? 300)
const ROWS = Number(process.env.ROWS ?? 20)
const ROOT = testKey(0xa0)
const WRITER = testKey(0x10)

const fixtures = new MaterializerFixture()
const { materializer } = await fixtures.open({ rootPrincipal: ROOT })
const transactions: ReplayProposal[] = []
let clock = 1n
async function add(author: Uint8Array, ...steps: Parameters<typeof replayProposal>[2]): Promise<void> {
  transactions.push(await replayProposal(clock, `tx-${clock}`, steps, materializer.executionManifestDigest, author))
  clock += 1n
}

await add(ROOT, 'CREATE TABLE items (id INTEGER PRIMARY KEY, grp INTEGER NOT NULL, value INTEGER NOT NULL)',
  'CREATE INDEX items_grp ON items (grp)')
await materializer.materialize(transactions)

const cpuMs: Record<string, number> = {}
async function phase(name: string, sql: (group: number) => string): Promise<void> {
  for (let group = 0; group < TXS; group += 1) await add(WRITER, sql(group))
  const started = process.cpuUsage()
  await materializer.materialize(transactions)
  const used = process.cpuUsage(started)
  cpuMs[name] = Math.round((used.user + used.system) / 1000)
}
const ids = (group: number) => Array.from({ length: ROWS }, (_value, row) => group * ROWS + row + 1)
await phase('insert', (group) => `INSERT INTO items (id, grp, value) VALUES ${ids(group).map((id) => `(${id}, ${group}, ${id})`).join(', ')}`)
await phase('update', (group) => `UPDATE items SET value = value + 1 WHERE grp = ${group}`)
await phase('delete', (group) => `DELETE FROM items WHERE grp = ${group}`)

const rejected = transactions.filter((transaction) => materializer.outcome(transaction.txId)?.outcome !== 'accepted').length
materializer.close()
await fixtures.cleanup()
if (rejected > 0) throw new Error(`${rejected} transactions rejected`)
console.log(JSON.stringify({ transactions: TXS, rowsPerTransaction: ROWS, cpuMs }))

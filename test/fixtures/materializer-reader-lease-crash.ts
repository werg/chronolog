import { DeterministicMaterializer } from '../../packages/materializer-doltlite/src/materializer.js'
import { createNativeSqlEngine } from '../../packages/materializer-doltlite/src/native.js'
import { replayProposal, ROOT_KEY } from '../../packages/materializer-doltlite/src/test-fixtures.js'
const path = process.argv[2]
if (path === undefined) throw new Error('PATH_REQUIRED')
const materializer = await DeterministicMaterializer.open({ path, engine: createNativeSqlEngine(), rootAdministrator: ROOT_KEY, checkpointEvery: 1 })
const first = await replayProposal(1n, 'first', [
  'CREATE TABLE crash_view (id INTEGER PRIMARY KEY, value TEXT)',
  "INSERT INTO crash_view (id, value) VALUES (1, 'first')",
], materializer.executionManifestDigest)
const second = await replayProposal(2n, 'second', ["UPDATE crash_view SET value = 'second' WHERE id = 1"], materializer.executionManifestDigest)
await materializer.materialize([first])
const heldFirst = materializer.captureRead()
await materializer.materialize([first, second])
const heldSecond = materializer.captureRead()
await materializer.materialize([first])
const firstValue = heldFirst.query('SELECT value FROM crash_view').rows[0]?.[0]
const secondValue = heldSecond.query('SELECT value FROM crash_view').rows[0]?.[0]
if (firstValue?.kind !== 'text' || firstValue.value !== 'first' ||
    secondValue?.kind !== 'text' || secondValue.value !== 'second') throw new Error('LEASE_NOT_COHERENT')
process.kill(process.pid, 'SIGKILL')

import {
  DeterministicMaterializer,
  createNativeSqlEngine,
  type ReplayProposal,
  type MaterializerPublicationFaultPoint,
} from '@chronolog/materializer-doltlite'
import {
  encodeTransactionCore,
  transactionDigest,
  utf8,
  type TransactionCore,
} from '@chronolog/protocol'

const [path, requestedPoint] = process.argv.slice(2)
if (path === undefined || requestedPoint === undefined) throw new Error('CRASH_FIXTURE_ARGUMENTS_REQUIRED')
const point = requestedPoint as MaterializerPublicationFaultPoint
const engine = createNativeSqlEngine()
const materializer = await DeterministicMaterializer.open({
  path,
  engine,
  // The probe's author is the root administrator, so it may create the table.
  rootAdministrator: bytes32(4),
  checkpointEvery: 1,
  publicationFaultInjector(candidate) {
    if (candidate === point) process.kill(process.pid, 'SIGKILL')
  },
})
const core: TransactionCore = {
  operationId: 'publication-crash',
  groupId: bytes32(1),
  membershipRevision: bytes32(2),
  validationPolicy: bytes32(3),
  authorId: bytes32(4),
  authorTimestampMs: 1n,
  nonce: bytes32(5),
  executionManifestDigest: materializer.executionManifestDigest,
  program: {
    version: 3,
    steps: [{ sql: 'CREATE TABLE crash_probe (id INTEGER PRIMARY KEY) STRICT', bindings: [] }],
  },
}
const canonicalCandidate = encodeTransactionCore(core)
const transaction: ReplayProposal = {
  txId: utf8('crash-probe'),
  candidateDigest: await transactionDigest(canonicalCandidate),
  canonicalCandidate,
  core,
}
await materializer.materialize([transaction])
throw new Error(`CRASH_FIXTURE_POINT_NOT_REACHED:${point}`)

function bytes32(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff)
}

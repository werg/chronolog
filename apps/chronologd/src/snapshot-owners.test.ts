import { join } from 'node:path'

import {
  DeterministicMaterializer,
  openReadOnlyDatabase,
  readMaterializedRootAdministrator,
  type ReplayProposal,
} from '@chronolog/materializer-doltlite'
import { MaterializerFixture, replayProposal, rows, testKey } from '@chronolog/materializer-doltlite/testing'
import { commitStagedSnapshot, exportSnapshotArchive, signSnapshotManifest, stageSnapshotArchive, type TrustedSnapshotManifest } from '@chronolog/node-core'
import { generateEd25519KeyPair, platformObjectId, platformOp, type ExecutionManifest } from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import { applicationTableDigests, platformTableDigests } from './fork-seed.js'

const ROOT = testKey(0x40)
const ALICE = testKey(0x10)
const BOB = testKey(0x20)

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())

function digests(path: string): Record<string, string> {
  const database = openReadOnlyDatabase(path)
  try {
    return { ...applicationTableDigests(database), ...platformTableDigests(database) }
  } finally { database.close() }
}

async function validate(path: string, manifest: ExecutionManifest, rootAdministrator: Uint8Array, trusted: TrustedSnapshotManifest): Promise<void> {
  const materializer = await DeterministicMaterializer.open({ path, executionManifest: manifest, rootAdministrator })
  try {
    if (materializer.databaseContentHash !== trusted.databaseContentHash) throw new Error('SNAPSHOT_MATERIALIZED_EVIDENCE_MISMATCH')
  } finally { materializer.close() }
}

describe('snapshot export and import of owner-controlled rows', () => {
  it('carries owners, platform tables and platform triggers, and refuses another group\'s root', async () => {
    const { materializer, path, manifest } = await fixtures.open({ rootAdministrator: ROOT })
    const transactions: ReplayProposal[] = []
    let clock = 1n
    const submit = async (author: Uint8Array, ...steps: Parameters<typeof replayProposal>[2]): Promise<Uint8Array> => {
      const transaction = await replayProposal(clock, `tx-${clock}`, steps, materializer.executionManifestDigest, author)
      clock += 1n
      transactions.push(transaction)
      await materializer.materialize(transactions)
      expect(materializer.outcome(transaction.txId)?.outcome).toBe('accepted')
      return transaction.txId
    }
    await submit(ROOT, 'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)')
    await submit(ALICE, "INSERT INTO notes (id, body) VALUES (1, 'alice')")
    await submit(BOB, "INSERT INTO notes (id, body) VALUES (2, 'bob')")
    const team = await submit(ALICE, platformOp.createCollective({ governance: { insert: 'member', update: 'member', delete: 'admin' }, invitees: [BOB] }),
      platformOp.grant({ table: 'notes', grantee: BOB, operations: ['update'], rowKey: [1n] }))
    await submit(BOB, platformOp.acceptMembership(await platformObjectId(team, 0)))

    const signer = await generateEd25519KeyPair()
    const trusted: TrustedSnapshotManifest = {
      version: 1,
      groupId: testKey(1),
      executionManifestDigest: materializer.executionManifestDigest,
      materializedRevision: materializer.revision,
      orderLength: materializer.orderLength,
      databaseContentHash: materializer.databaseContentHash,
      transactionLogDigest: await materializer.transactionLogDigest(),
      feedHeads: [],
      createdAtMs: 1n,
    }
    materializer.close()
    const archive = join(await fixtures.directory(), 'archive')
    await exportSnapshotArchive({ archiveDirectory: archive, databasePath: path, signedManifest: await signSnapshotManifest(trusted, signer) })

    const expectations = { groupId: trusted.groupId, executionManifestDigest: trusted.executionManifestDigest, authorizedSigners: [signer.publicKeyBytes] }
    // A node of a group with another root administrator refuses the database.
    await expect(stageSnapshotArchive({
      archiveDirectory: archive,
      targetDatabasePath: join(await fixtures.directory(), 'foreign.db'),
      expectations,
      validateDatabase: async (staged, evidence) => validate(staged, manifest, testKey(0x77), evidence),
    })).rejects.toThrow('SNAPSHOT_STAGED_DATABASE_INVALID')

    // The importing node already has its own (empty) database for the group.
    const target = join(await fixtures.directory(), 'application.db')
    ;(await fixtures.open({ rootAdministrator: ROOT, path: target })).materializer.close()
    const staged = await stageSnapshotArchive({
      archiveDirectory: archive,
      targetDatabasePath: target,
      expectations,
      validateDatabase: async (stagedPath, evidence) => validate(stagedPath, manifest, ROOT, evidence),
    })
    await commitStagedSnapshot({ staged, targetDatabasePath: target, backupPath: `${target}.backup` })

    expect(readMaterializedRootAdministrator(target)).toEqual(ROOT)
    expect(digests(target)).toEqual(digests(path))
    const imported = await DeterministicMaterializer.open({ path: target, executionManifest: manifest, rootAdministrator: ROOT })
    try {
      expect(imported.databaseContentHash).toBe(trusted.databaseContentHash)
      expect(rows(imported, "SELECT name FROM sqlite_schema WHERE type = 'trigger' AND name LIKE 'chronolog_k_notes_%' ORDER BY name"))
        .toEqual([['chronolog_k_notes_del'], ['chronolog_k_notes_ins'], ['chronolog_k_notes_upd']])
      // Ownership keeps being enforced on the imported database.
      await imported.materialize([...transactions, await replayProposal(clock, 'after-import', ["UPDATE notes SET body = 'x' WHERE id = 2"], imported.executionManifestDigest, ALICE)])
      expect(imported.outcome(new TextEncoder().encode('after-import'))?.rejectionCode).toBe('policy:notes:update')
    } finally { imported.close() }
  })
})

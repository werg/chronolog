import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { encodeSignedGenesis } from '@chronolog/capabilities'
import { DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { MemoryOperationStore } from '@chronolog/node-core'
import { provisionMembership } from '@chronolog/node-core/membership'
import { generateEd25519KeyPair } from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import { resolveRootAdministrator } from '../apps/chronologd/src/root-administrator.js'
import { MaterializerFixture, admitted, rows } from '../packages/materializer-doltlite/src/test-fixtures.js'

const fixtures = new MaterializerFixture()
const directories: string[] = []
afterEach(async () => {
  await fixtures.cleanup()
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true })
})

describe('signed genesis SQL authority separation', () => {
  it('bootstraps SQL with the schema key and rejects the roster issuer as a schema administrator', async () => {
    const schemaIdentity = await generateEd25519KeyPair()
    const { materializer, path, manifest } = await fixtures.open({ rootAdministrator: schemaIdentity.publicKeyBytes })
    try {
      const provisioned = await provisionMembership({ store: new MemoryOperationStore(),
        executionManifestDigest: materializer.executionManifestDigest, schemaAdministratorPublicKey: schemaIdentity.publicKeyBytes,
        nativeAuthority: { historyId: 'h_0123456789abcdef0123456789abcdef', publicKey: schemaIdentity.publicKeyBytes } })
      const genesis = provisioned.descriptor.genesis
      expect(genesis.manifest.schemaAdminPublicKey).toEqual(schemaIdentity.publicKeyBytes)
      expect(genesis.manifest.rootAdminPublicKey).not.toEqual(schemaIdentity.publicKeyBytes)
      const directory = await mkdtemp(join(tmpdir(), 'chronolog-schema-key-'))
      directories.push(directory)
      await writeFile(join(directory, 'governance.json'), JSON.stringify({ signedGenesis: Buffer.from(encodeSignedGenesis(genesis)).toString('base64') }))
      expect(await resolveRootAdministrator(directory)).toEqual(schemaIdentity.publicKeyBytes)

      const rosterAttempt = await admitted(1n, 'roster-ddl', ['CREATE TABLE roster_owned (id INTEGER PRIMARY KEY)'],
        materializer.executionManifestDigest, genesis.manifest.rootAdminPublicKey)
      const schemaChange = await admitted(2n, 'schema-ddl', ['CREATE TABLE application_owned (id INTEGER PRIMARY KEY)'],
        materializer.executionManifestDigest, genesis.manifest.schemaAdminPublicKey)
      await materializer.materialize([rosterAttempt, schemaChange])
      expect(materializer.outcome(rosterAttempt.txId)).toMatchObject({ outcome: 'rejected' })
      expect(materializer.outcome(schemaChange.txId)).toMatchObject({ outcome: 'accepted' })
      expect(rows(materializer, "SELECT name FROM sqlite_schema WHERE name IN ('roster_owned', 'application_owned') ORDER BY name"))
        .toEqual([['application_owned']])
      materializer.close()
      await expect(DeterministicMaterializer.open({ path, executionManifest: manifest,
        rootAdministrator: genesis.manifest.rootAdminPublicKey })).rejects.toThrow('DATABASE_ROOT_ADMINISTRATOR_MISMATCH')
    } finally { materializer.close() }
  })
})

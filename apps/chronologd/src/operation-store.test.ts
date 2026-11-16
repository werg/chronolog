import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NodeStateDatabase } from '@chronolog/control-store'
import { DurableOperationJournal } from '@chronolog/node-core'
import { expect, it } from 'vitest'

import { SqliteOperationStore } from './operation-store.js'

it('recovers exact unpublished operation bytes after closing and reopening durable node state', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-operations-'))
  let database = new NodeStateDatabase(join(directory, 'node-state.sqlite'))
  try {
    const journal = new DurableOperationJournal(new SqliteOperationStore(database.database), 'governance')
    await expect(journal.run({
      operationId: 'approval', fingerprint: Uint8Array.of(1), prepare: async () => Uint8Array.of(9, 8, 7),
      apply: async () => { throw new Error('process stopped before publication') },
    })).rejects.toThrow('process stopped before publication')
    database.close()
    database = new NodeStateDatabase(join(directory, 'node-state.sqlite'))
    const recovered = new DurableOperationJournal(new SqliteOperationStore(database.database), 'governance')
    const published: Uint8Array[] = []
    const result = await recovered.run({
      operationId: 'approval', fingerprint: Uint8Array.of(1),
      prepare: async () => { throw new Error('must not reauthor') },
      apply: async (bytes) => { published.push(bytes) },
    })
    expect(result).toEqual(Uint8Array.of(9, 8, 7))
    expect(published).toEqual([Uint8Array.of(9, 8, 7)])
  } finally {
    database.close()
    await rm(directory, { recursive: true, force: true })
  }
})

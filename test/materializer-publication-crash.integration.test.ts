import { spawnSync } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import {
  DeterministicMaterializer,
  createDoltLiteExecutionManifest,
  type MaterializerPublicationFaultPoint,
} from '@chronolog/materializer-doltlite'
import { afterEach, describe, expect, it } from 'vitest'

const directories: string[] = []
const prePublication: readonly MaterializerPublicationFaultPoint[] = [
  'after_candidate_commit',
  'after_revision_ref_created',
  'before_head_publish',
]
const postPublication: readonly MaterializerPublicationFaultPoint[] = [
  'after_head_publish',
  'after_reader_swap',
]

afterEach(async () => Promise.all(
  directories.splice(0).map((path) => rm(path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })),
))

describe('native publication crash recovery', () => {
  for (const point of [...prePublication, ...postPublication]) {
    it(`recovers an abrupt process death at ${point}`, async () => {
      const directory = await mkdtemp(join(tmpdir(), 'chronolog-publication-crash-'))
      directories.push(directory)
      const path = join(directory, 'application.db')
      const result = spawnSync(
        process.execPath,
        ['--import', 'tsx', resolve('test/fixtures/materializer-publication-crash.ts'), path, point],
        { cwd: resolve('.'), encoding: 'utf8', timeout: 20_000 },
      )
      // Load the TypeScript hook in the process under test. No CLI wrapper or
      // auxiliary IPC server is needed to observe its real abrupt death.
      expect(
        result.signal === 'SIGKILL' || result.status === 128 + 9,
        `${result.stdout}\n${result.stderr}`,
      ).toBe(true)

      const manifest = createDoltLiteExecutionManifest({ profile: 'chronolog-native-production-v1' })
      const reopened = await DeterministicMaterializer.open({
        path,
        executionManifest: manifest,
        rootAdministrator: Uint8Array.from({ length: 32 }, (_value, index) => (4 + index) & 0xff),
        checkpointEvery: 1,
      })
      try {
        const published = postPublication.includes(point)
        expect(reopened.revision).toBe(published ? 1n : 0n)
        expect(reopened.orderLength).toBe(published ? 1 : 0)
        expect(reopened.localSql(
          "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'crash_probe'",
        ).rows).toEqual([pinnedCount(published ? '1' : '0')])
      } finally {
        reopened.close()
      }
    })
  }
})

function pinnedCount(value: string) {
  return [{ kind: 'integer' as const, value }]
}

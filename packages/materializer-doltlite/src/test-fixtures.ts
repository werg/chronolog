import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  encodeTransactionCore,
  sqlStatement,
  transactionDigest,
  utf8,
  type ExecutionLimits,
  type ExecutionManifest,
  type ProgramStep,
  type TransactionCore,
} from '@chronolog/protocol'

import { createDoltLiteExecutionManifest } from './manifest.js'
import { DeterministicMaterializer } from './materializer.js'
import type { AdmittedTransaction, LocalSqlValue, MaterializerOptions } from './types.js'

/** Test-only helpers for driving a real materializer with signed-looking transactions. */

export const ROOT_KEY = testKey(0xa0)

export function testKey(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff)
}

export class MaterializerFixture {
  readonly #directories: string[] = []

  async open(options: {
    readonly limits?: Partial<ExecutionLimits>
    readonly rootAdministrator?: Uint8Array
    readonly forkSeeding?: boolean
    readonly checkpointEvery?: number
    readonly path?: string
  } = {}): Promise<{ readonly materializer: DeterministicMaterializer; readonly path: string; readonly manifest: ExecutionManifest }> {
    const path = options.path ?? join(await this.directory(), 'application.db')
    const manifest = createDoltLiteExecutionManifest(options.limits === undefined ? {} : { limits: options.limits })
    const materializerOptions: MaterializerOptions = {
      path,
      executionManifest: manifest,
      rootAdministrator: options.rootAdministrator ?? ROOT_KEY,
      ...(options.forkSeeding === undefined ? {} : { forkSeeding: options.forkSeeding }),
      ...(options.checkpointEvery === undefined ? {} : { checkpointEvery: options.checkpointEvery }),
    }
    return { materializer: await DeterministicMaterializer.open(materializerOptions), path, manifest }
  }

  async directory(): Promise<string> {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-materializer-'))
    this.#directories.push(directory)
    return directory
  }

  async cleanup(): Promise<void> {
    await Promise.all(this.#directories.splice(0).map((path) => rm(path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })))
  }
}

/**
 * An admitted transaction with id `id`, authored by `author` at `timestamp`.
 * String steps are SQL without parameters.
 */
export async function admitted(
  timestamp: bigint,
  id: string,
  steps: readonly (ProgramStep | string)[],
  executionManifestDigest: Uint8Array,
  author: Uint8Array = ROOT_KEY,
): Promise<AdmittedTransaction> {
  const core: TransactionCore = {
    groupId: testKey(1), membershipRevision: testKey(2), validationPolicy: testKey(3), authorId: author,
    authorTimestampMs: timestamp, nonce: testKey(Number(timestamp % 200n) + 10), executionManifestDigest,
    program: { version: 2, steps: steps.map((step) => typeof step === 'string' ? sqlStatement(step) : step) },
  }
  const canonicalCandidate = encodeTransactionCore(core)
  return {
    txId: utf8(id),
    authorFeedSequence: timestamp,
    candidateDigest: await transactionDigest(canonicalCandidate),
    canonicalCandidate,
    core,
  }
}

export function rows(materializer: DeterministicMaterializer, sql: string, parameters: readonly LocalSqlValue[] = []): unknown[][] {
  return materializer.localSql(sql, parameters).rows.map((row) => row.map(plain))
}

function plain(value: LocalSqlValue): unknown {
  return value.kind === 'null' ? null : value.value
}

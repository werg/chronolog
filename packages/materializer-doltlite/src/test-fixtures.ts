import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  encodeTransactionCore,
  sqlStatement,
  transactionDigest,
  type ExecutionLimits,
  type ExecutionManifest,
  type ProgramStep,
  type TransactionCore,
} from '@chronolog/protocol'

import { createNativeSqlEngine } from './native.js'
import { DeterministicMaterializer } from './materializer.js'
import type { ReplayProposal, LocalSqlValue, MaterializerOptions } from './types.js'

/** Test-only helpers for driving a real materializer with signed-looking transactions. */

export const ROOT_KEY = testKey(0xa0)

export function testKey(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff)
}

export class MaterializerFixture {
  readonly #directories: string[] = []

  async open(options: {
    readonly limits?: Partial<ExecutionLimits>
    readonly rootPrincipal?: Uint8Array
    readonly forkSeeding?: boolean
    readonly checkpointEvery?: number
    readonly path?: string
  } = {}): Promise<{ readonly materializer: DeterministicMaterializer; readonly path: string; readonly manifest: ExecutionManifest }> {
    const path = options.path ?? join(await this.directory(), 'application.db')
    const engine = createNativeSqlEngine(options.limits === undefined ? {} : { limits: options.limits })
    const manifest = engine.executionManifest
    const materializerOptions: MaterializerOptions = {
      path,
      engine,
      rootPrincipal: options.rootPrincipal ?? ROOT_KEY,
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
 * A replay proposal with id `id`, authored by `author` at `timestamp`.
 * String steps are SQL without parameters.
 */
export async function replayProposal(
  timestamp: bigint,
  id: string,
  steps: readonly (ProgramStep | string)[],
  executionManifestDigest: Uint8Array,
  author: Uint8Array = ROOT_KEY,
): Promise<ReplayProposal> {
  const core: TransactionCore = {
    operationId: id,
    groupId: testKey(1), membershipRevision: testKey(2), validationPolicy: testKey(3), authorId: author,
    authorTimestampMs: timestamp, nonce: testKey(Number(timestamp % 200n) + 10), executionManifestDigest,
    program: { version: 3, steps: steps.map((step) => typeof step === 'string' ? sqlStatement(step) : step) },
  }
  const canonicalCandidate = encodeTransactionCore(core)
  return {
    txId: await transactionDigest(canonicalCandidate),
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

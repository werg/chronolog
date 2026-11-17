import { describe, expect, it } from 'vitest'
import { emit, encodeTransactionCore, program, transactionDigest, type TransactionCore } from '@chronolog/protocol'

import {
  decodeMaterializationInvocation,
  decodeReplaySuffix,
  digestReplayOrder,
  encodeMaterializationInvocation,
  encodeReplaySuffix,
  type ChronologArtifactKind,
  type ChronologMaterializationInvocation,
  type ChronologReplaySuffix,
  type ExactArtifactRef,
  type ExactDatabaseRef,
} from './index.js'

const storeId = Uint8Array.of(1, 2, 3)
const digest32 = (seed: number) => Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff)
const digest20 = (seed: number) => Uint8Array.from({ length: 20 }, (_value, index) => (seed + index) & 0xff)

function artifact(kind: ChronologArtifactKind, seed: number): ExactArtifactRef {
  return {
    kind,
    formatVersion: 1,
    object: {
      storeId,
      codec: { number: seed + 1, version: 1 },
      contentId: { algorithm: 'sha2-256', digest: digest32(seed) },
    },
  }
}

const database: ExactDatabaseRef = {
  storeId,
  doltFormatVersion: 1,
  canonicalGenesisCommit: { doltFormatVersion: 1, contentId: { algorithm: 'dolt-blake3-160', digest: digest20(1) } },
  commitHash: { doltFormatVersion: 1, contentId: { algorithm: 'dolt-blake3-160', digest: digest20(2) } },
  stateDigest: { stateFormatVersion: 1, contentId: { algorithm: 'sha2-256', digest: digest32(3) } },
}

describe('portable SQL materialization invocation', () => {
  it('retains original proposal bytes and reconstructs their core through a replay suffix', async () => {
    const core: TransactionCore = {
      operationId: 'preview', groupId: digest32(1), membershipRevision: digest32(2),
      validationPolicy: digest32(3), authorId: digest32(4), authorTimestampMs: 500n,
      nonce: digest32(5), executionManifestDigest: digest32(6), program: program(emit('note', 'local preview')),
    }
    const canonicalCandidate = encodeTransactionCore(core), txId = digest32(7)
    const suffix: ChronologReplaySuffix = {
      version: 1, groupId: core.groupId, replayFromIndex: 2, targetOrderLength: 3,
      targetOrderDigest: await digestReplayOrder([digest32(8), digest32(9), txId]),
      transactions: [{ txId, canonicalCandidate, candidateDigest: await transactionDigest(canonicalCandidate), core }],
    }
    expect(decodeReplaySuffix(encodeReplaySuffix(suffix))).toEqual(suffix)
  })

  it('round-trips without an external schema artifact or digest', () => {
    const invocation: ChronologMaterializationInvocation = {
      version: 1,
      profile: 'pure',
      context: { groupId: digest32(4), logicalTimeMs: null, entropySeed: null },
      previous: null,
      replayBase: { manifest: artifact('materialization-manifest', 5), database },
      replaySuffix: artifact('replay-suffix', 6),
      executionManifest: artifact('execution-manifest', 7),
      continuation: null,
      expectedEngineDigest: digest32(8),
      expectedExecutionManifestDigest: digest32(9),
      expectedPreviousOrderDigest: digest32(10),
      replayFromIndex: 0,
      targetOrderLength: 2,
      targetOrderDigest: digest32(11),
    }
    const decoded = decodeMaterializationInvocation(encodeMaterializationInvocation(invocation))
    expect(decoded).toEqual(invocation)
    expect(decoded).not.toHaveProperty('schemaManifest')
    expect(decoded).not.toHaveProperty('expectedSchemaDigest')
  })
})

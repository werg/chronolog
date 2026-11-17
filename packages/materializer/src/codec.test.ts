import { describe, expect, it } from 'vitest'
import { DEFAULT_DECODE_LIMITS, assertCanonicalCbor, encodeCanonicalCbor, expectMap } from '@chronolog/canonical'
import { emit, encodeTransactionCore, program, transactionDigest, utf8, type TransactionCore } from '@chronolog/protocol'

import {
  decodeAdmittedSuffix,
  decodeMaterializationInvocation,
  encodeAdmittedSuffix,
  encodeMaterializationInvocation,
  type ChronologAdmittedSuffix,
  type ChronologArtifactKind,
  type ChronologMaterializationInvocation,
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
  it('round-trips without an external schema artifact or digest', () => {
    const invocation: ChronologMaterializationInvocation = {
      version: 1,
      profile: 'pure',
      context: { groupId: digest32(4), logicalTimeMs: null, entropySeed: null },
      previous: null,
      replayBase: { manifest: artifact('materialization-manifest', 5), database },
      admittedSuffix: artifact('admitted-suffix', 6),
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

describe('transport-independent admitted suffix', () => {
  async function suffix(): Promise<ChronologAdmittedSuffix> {
    const core: TransactionCore = {
      operationId: 'message-1', groupId: digest32(1), membershipRevision: digest32(2),
      validationPolicy: digest32(3), authorId: digest32(4), authorTimestampMs: 10n,
      nonce: digest32(5), executionManifestDigest: digest32(6), program: program(emit('chat', 'hello')),
    }
    const canonicalCandidate = encodeTransactionCore(core)
    return {
      version: 2, groupId: core.groupId, replayFromIndex: 0, targetOrderLength: 1, targetOrderDigest: digest32(7),
      transactions: [{ txId: utf8('proposal-1'), candidateDigest: await transactionDigest(canonicalCandidate), canonicalCandidate, core }],
    }
  }

  it('round-trips only the stable proposal identity and signed candidate', async () => {
    const input = await suffix()
    expect(decodeAdmittedSuffix(encodeAdmittedSuffix(input))).toEqual(input)
    const encoded = expectMap(assertCanonicalCbor(encodeAdmittedSuffix(input), DEFAULT_DECODE_LIMITS), 'suffix')
    const transaction = input.transactions[0]!
    expect(encoded.get(5n)).toEqual([[transaction.txId, transaction.candidateDigest, transaction.canonicalCandidate]])
  })

  it('rejects the retired suffix version and transport-bearing transaction tuple', async () => {
    const input = await suffix()
    const original = expectMap(assertCanonicalCbor(encodeAdmittedSuffix(input), DEFAULT_DECODE_LIMITS), 'suffix')
    const oldVersion = new Map(original)
    oldVersion.set(0n, 1n)
    expect(() => decodeAdmittedSuffix(encodeCanonicalCbor(oldVersion))).toThrow('Unsupported admitted suffix version')

    const obsoleteTuple = new Map(original)
    const transaction = input.transactions[0]!
    obsoleteTuple.set(5n, [[transaction.txId, 123n, transaction.candidateDigest, transaction.canonicalCandidate]])
    expect(() => decodeAdmittedSuffix(encodeCanonicalCbor(obsoleteTuple))).toThrow('invalid arity')
  })
})

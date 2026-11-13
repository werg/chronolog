import {
  MaterializerContractError,
  digestAdmittedOrder,
  type ChronologMaterializationOutcome,
  type ResolvedMaterializationInvocation,
} from '@chronolog/materializer'
import { encodeTransactionCore, type TransactionCore } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import {
  createDoltLitePortableKernel,
  type DoltLitePortableMaterializerLike,
  type DoltLitePortableProjectionContext,
} from './portable.js'
import type { AdmittedTransaction, MaterializedRevision, TransactionLogRow } from './types.js'

const bytes = (fill: number, length = 32): Uint8Array => new Uint8Array(length).fill(fill)

const engineDigest = bytes(0xe1)
const manifestDigest = bytes(0xe2)

function core(index: number): TransactionCore {
  return {
    groupId: bytes(0x01),
    membershipRevision: bytes(0x02),
    validationPolicy: bytes(0x03),
    authorId: bytes(0x04),
    authorTimestampMs: 1_000n + BigInt(index),
    nonce: bytes(0x80 + index),
    executionManifestDigest: manifestDigest,
    program: { version: 1, statements: [{ sql: `INSERT INTO t VALUES (${index})`, bindings: [] }] },
  }
}

function transaction(index: number): AdmittedTransaction {
  const value = core(index)
  return {
    txId: bytes(0x10 + index),
    authorFeedSequence: BigInt(index + 1),
    candidateDigest: bytes(0x20 + index),
    canonicalCandidate: encodeTransactionCore(value),
    core: value,
  }
}

function logRow(item: AdmittedTransaction, orderIndex: number): TransactionLogRow {
  return {
    txId: item.txId,
    orderKey: { authorTimestampMs: item.core.authorTimestampMs, authorId: item.core.authorId, authorFeedSequence: item.authorFeedSequence, txId: item.txId },
    orderIndex,
    outcome: 'accepted',
    rejectionCode: null,
    failingStatementIndex: null,
    authorId: item.core.authorId,
    authorTimestampMs: item.core.authorTimestampMs,
    authorFeedSequence: item.authorFeedSequence,
    candidateDigest: item.candidateDigest,
    canonicalCandidate: item.canonicalCandidate,
  }
}

interface FakeMaterializer extends DoltLitePortableMaterializerLike {
  readonly calls: AdmittedTransaction[][]
  orderLength: number
  log: TransactionLogRow[]
  /** Optional corruption of the log after materialize, to model a misbehaving engine. */
  afterMaterialize?: (log: TransactionLogRow[]) => TransactionLogRow[]
}

function fakeMaterializer(prior: readonly AdmittedTransaction[]): FakeMaterializer {
  const fake: FakeMaterializer = {
    revision: BigInt(prior.length),
    orderLength: prior.length,
    executionManifestDigest: manifestDigest,
    backend: { engine: 'doltlite', engineDigest } as unknown as FakeMaterializer['backend'],
    calls: [],
    log: prior.map(logRow),
    transactionLog() { return fake.log },
    async materialize(ordered) {
      fake.calls.push([...ordered])
      fake.log = ordered.map(logRow)
      if (fake.afterMaterialize) fake.log = fake.afterMaterialize(fake.log)
      fake.orderLength = fake.log.length
      return { revision: 1n, orderLength: ordered.length } as unknown as MaterializedRevision
    },
  }
  return fake
}

async function invocation(
  prior: readonly AdmittedTransaction[],
  replayFromIndex: number,
  suffix: readonly AdmittedTransaction[],
  overrides: Record<string, unknown> = {},
  inputOverrides: Partial<ResolvedMaterializationInvocation> = {},
): Promise<ResolvedMaterializationInvocation> {
  const target = [...prior.slice(0, replayFromIndex), ...suffix]
  return {
    invocation: {
      continuation: null,
      expectedEngineDigest: engineDigest,
      expectedExecutionManifestDigest: manifestDigest,
      expectedPreviousOrderDigest: await digestAdmittedOrder(prior.map((item) => item.txId)),
      replayFromIndex,
      targetOrderLength: target.length,
      targetOrderDigest: await digestAdmittedOrder(target.map((item) => item.txId)),
      ...overrides,
    },
    continuation: null,
    admittedSuffix: { transactions: suffix },
    exactReadSet: [],
    executionManifest: {},
    ...inputOverrides,
  } as unknown as ResolvedMaterializationInvocation
}

const outcome = { kind: 'completed' } as unknown as ChronologMaterializationOutcome

function kernelFor(materializer: DoltLitePortableMaterializerLike) {
  const projections: DoltLitePortableProjectionContext[] = []
  const kernel = createDoltLitePortableKernel(materializer, (context) => {
    projections.push(context)
    return outcome
  })
  return { kernel, projections }
}

async function contractCode(promise: Promise<unknown>): Promise<string> {
  const error = await promise.then(() => null, (caught: unknown) => caught)
  expect(error).toBeInstanceOf(MaterializerContractError)
  return (error as MaterializerContractError).code
}

const prior = [transaction(0), transaction(1), transaction(2)]

describe('DoltLite portable kernel', () => {
  it('replays the retained prefix plus the admitted suffix and projects the result', async () => {
    const materializer = fakeMaterializer(prior)
    const { kernel, projections } = kernelFor(materializer)
    const suffix = [transaction(5), transaction(6)]
    await expect(kernel.materialize(await invocation(prior, 2, suffix))).resolves.toBe(outcome)
    expect(materializer.calls).toHaveLength(1)
    expect(materializer.calls[0]!.map((item) => item.txId[0])).toEqual([0x10, 0x11, 0x15, 0x16])
    // The prefix is rebuilt by decoding the canonical candidate, not trusted from caller input.
    expect(materializer.calls[0]![0]!.core).toEqual(core(0))
    expect(projections).toHaveLength(1)
    expect(projections[0]!.transactionLog).toHaveLength(4)
  })

  it('does not alias caller-owned transaction bytes into the engine', async () => {
    const materializer = fakeMaterializer([])
    const { kernel } = kernelFor(materializer)
    const suffix = [transaction(0)]
    await kernel.materialize(await invocation([], 0, suffix))
    expect(materializer.calls[0]![0]!.txId).not.toBe(suffix[0]!.txId)
    expect(materializer.calls[0]![0]!.canonicalCandidate).not.toBe(suffix[0]!.canonicalCandidate)
  })

  it('rejects an engine digest mismatch before touching the materializer', async () => {
    const materializer = fakeMaterializer(prior)
    const { kernel } = kernelFor(materializer)
    expect(await contractCode(kernel.materialize(await invocation(prior, 3, [], { expectedEngineDigest: bytes(0x99) }))))
      .toBe('MATERIALIZER_ORACLE_ENGINE_DIGEST_MISMATCH')
    expect(await contractCode(kernel.materialize(await invocation(prior, 3, [], { expectedEngineDigest: engineDigest.slice(1) }))))
      .toBe('MATERIALIZER_ORACLE_ENGINE_DIGEST_MISMATCH')
    expect(materializer.calls).toEqual([])
  })

  it('rejects an execution manifest digest mismatch', async () => {
    const materializer = fakeMaterializer(prior)
    const { kernel } = kernelFor(materializer)
    expect(await contractCode(kernel.materialize(await invocation(prior, 3, [], { expectedExecutionManifestDigest: bytes(0x99) }))))
      .toBe('MATERIALIZER_ORACLE_EXECUTION_MANIFEST_DIGEST_MISMATCH')
    expect(materializer.calls).toEqual([])
  })

  it('rejects continuations, which the oracle cannot honour', async () => {
    const materializer = fakeMaterializer(prior)
    const { kernel } = kernelFor(materializer)
    const input = await invocation(prior, 3, [], {}, { continuation: {} as ResolvedMaterializationInvocation['continuation'] })
    expect(await contractCode(kernel.materialize(input))).toBe('MATERIALIZER_ORACLE_CONTINUATION_UNSUPPORTED')
    expect(materializer.calls).toEqual([])
  })

  it('rejects a local log whose length disagrees with the recorded order length', async () => {
    const materializer = fakeMaterializer(prior)
    materializer.orderLength = 2
    const { kernel } = kernelFor(materializer)
    expect(await contractCode(kernel.materialize(await invocation(prior, 3, []))))
      .toBe('MATERIALIZER_ORACLE_LOG_LENGTH_MISMATCH')
  })

  it('rejects an invocation built against a different previous order', async () => {
    const materializer = fakeMaterializer(prior)
    const { kernel } = kernelFor(materializer)
    const forked = [transaction(0), transaction(1), transaction(9)]
    expect(await contractCode(kernel.materialize(await invocation(forked, 3, []))))
      .toBe('MATERIALIZER_PREVIOUS_ORDER_DIGEST_MISMATCH')
    expect(materializer.calls).toEqual([])
  })

  it('rejects a replay point beyond the retained log', async () => {
    const materializer = fakeMaterializer(prior)
    const { kernel } = kernelFor(materializer)
    expect(await contractCode(kernel.materialize(await invocation(prior, 4, []))))
      .toBe('MATERIALIZER_REPLAY_PREFIX_UNAVAILABLE')
  })

  it('rejects a suffix whose length does not reach the target', async () => {
    const materializer = fakeMaterializer(prior)
    const { kernel } = kernelFor(materializer)
    const input = await invocation(prior, 3, [transaction(5)], { targetOrderLength: 5 })
    expect(await contractCode(kernel.materialize(input))).toBe('MATERIALIZER_TARGET_ORDER_LENGTH_MISMATCH')
    expect(materializer.calls).toEqual([])
  })

  it('rejects a suffix whose order differs from the committed target digest', async () => {
    const materializer = fakeMaterializer(prior)
    const { kernel } = kernelFor(materializer)
    const committed = await invocation(prior, 3, [transaction(5), transaction(6)])
    // Same length, swapped order.
    const swapped = { ...committed, admittedSuffix: { ...committed.admittedSuffix, transactions: [transaction(6), transaction(5)] } }
    expect(await contractCode(kernel.materialize(swapped))).toBe('MATERIALIZER_TARGET_ORDER_DIGEST_MISMATCH')
    // Same length, substituted transaction.
    const substituted = { ...committed, admittedSuffix: { ...committed.admittedSuffix, transactions: [transaction(5), transaction(7)] } }
    expect(await contractCode(kernel.materialize(substituted))).toBe('MATERIALIZER_TARGET_ORDER_DIGEST_MISMATCH')
    expect(materializer.calls).toEqual([])
  })

  it('rejects a negative replay index that would silently drop retained history', async () => {
    const materializer = fakeMaterializer(prior)
    const { kernel } = kernelFor(materializer)
    // slice(0, -1) keeps two rows; the target digest still binds the full order.
    const honest = await invocation(prior, 3, [transaction(5)])
    const input = { ...honest, invocation: { ...honest.invocation, replayFromIndex: -1 } }
    expect(await contractCode(kernel.materialize(input))).toBe('MATERIALIZER_TARGET_ORDER_LENGTH_MISMATCH')
    expect(materializer.calls).toEqual([])
  })

  it('rejects an engine whose final log length disagrees with the target', async () => {
    const materializer = fakeMaterializer(prior)
    materializer.afterMaterialize = (log) => log.slice(0, -1)
    const { kernel, projections } = kernelFor(materializer)
    expect(await contractCode(kernel.materialize(await invocation(prior, 3, [transaction(5)]))))
      .toBe('MATERIALIZER_ORACLE_FINAL_LOG_LENGTH_MISMATCH')
    expect(projections).toEqual([])
  })

  it('rejects an engine whose final log order differs from the target', async () => {
    const materializer = fakeMaterializer(prior)
    materializer.afterMaterialize = (log) => [log[1]!, log[0]!, ...log.slice(2)]
    const { kernel, projections } = kernelFor(materializer)
    expect(await contractCode(kernel.materialize(await invocation(prior, 3, [transaction(5)]))))
      .toBe('MATERIALIZER_ORACLE_FINAL_ORDER_MISMATCH')
    expect(projections).toEqual([])
  })

  it('hands the projector copies, so it cannot mutate oracle state', async () => {
    const materializer = fakeMaterializer([])
    const kernel = createDoltLitePortableKernel(materializer, (context) => {
      context.transactionLog[0]!.txId.fill(0)
      return outcome
    })
    await kernel.materialize(await invocation([], 0, [transaction(0)]))
    expect(materializer.log[0]!.txId).toEqual(bytes(0x10))
  })
})

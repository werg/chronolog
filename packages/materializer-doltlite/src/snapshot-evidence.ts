import { encodeCanonicalCbor, hashDomain, DOMAINS, type CborValue } from '@chronolog/protocol'

import type { TransactionLogRow } from './types.js'

/** Exact digest of every protected materialized-log field in order. */
export function materializedLogDigest(rows: readonly TransactionLogRow[]): Promise<Uint8Array> {
  const encoded = encodeCanonicalCbor(rows.map((row) => new Map<bigint, CborValue>([
    [0n, row.txId],
    [1n, BigInt(row.orderIndex)],
    [2n, row.authorId],
    [3n, row.authorTimestampMs],
    [4n, row.candidateDigest],
    [5n, row.canonicalCandidate],
    [6n, row.outcome],
    [7n, row.rejectionCode],
    [8n, row.failingStatementIndex === null ? null : BigInt(row.failingStatementIndex)],
  ])))
  return hashDomain(DOMAINS.materializedLog, encoded)
}

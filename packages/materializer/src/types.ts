import type { TransactionCore } from '@chronolog/protocol'

/**
 * An authenticated original proposal eligible for authored-time replay.
 * Inputs must be strictly compareTransactionOrder-ordered; admission/finality
 * evidence is verified by the owning replica, never inferred from transport.
 * txId = candidateDigest = transactionDigest(canonicalCandidate), where
 * canonicalCandidate is the raw canonical TransactionCore encoding.
 */
export interface ReplayProposal {
  readonly txId: Uint8Array
  readonly candidateDigest: Uint8Array
  readonly canonicalCandidate: Uint8Array
  readonly core: TransactionCore
}

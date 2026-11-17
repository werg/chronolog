import type { TransactionCore } from '@chronolog/protocol'

/**
 * An original signed proposal selected by the verified history owner for replay.
 * The materializer executes the supplied order and never infers admission or
 * settlement from transport roles or a separate ordering implementation.
 */
export interface ReplayProposal {
  readonly txId: Uint8Array
  readonly candidateDigest: Uint8Array
  readonly canonicalCandidate: Uint8Array
  readonly core: TransactionCore
}

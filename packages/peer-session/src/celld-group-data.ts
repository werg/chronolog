import type { OperationState, PeerIdentity, PeerRevision } from '@chronolog/peer-generation'
import type { ChangeProgram } from '@chronolog/protocol'
import type { ApplicationSession } from './session.js'
import type { CommandOptions, QueryParameter, QueryRows } from './session-types.js'
import { deferredStream } from './deferred-stream.js'

interface GroupQuery {
  readonly sql: string
  readonly bindings?: readonly QueryParameter[]
}

export interface CelldGroupQueryResult extends QueryRows {
  readonly revision: PeerRevision
}

/** A workspace may share one node session among multiple authenticated accounts. */
export function celldGroupData(session: ApplicationSession) {
  const requireGrant = (author: string, role: 'reader' | 'writer') => {
    if (session.memberGrant(author)?.[role] !== true) throw new Error('CELLD_GROUP_MEMBER_FORBIDDEN')
  }

  const query = async (author: string, input: GroupQuery & { readonly revision?: PeerRevision }): Promise<CelldGroupQueryResult> => {
    requireGrant(author, 'reader')
    const captured = structuredClone(input)
    const view = await session.readView()
    try {
      requireGrant(author, 'reader')
      const expected = captured.revision, current = view.revision
      if (expected !== undefined && (expected.applicationId !== current.applicationId || expected.historyId !== current.historyId ||
        expected.generation !== current.generation || expected.controlRevision !== current.controlRevision ||
        expected.point.generation !== current.point.generation || expected.point.sequence !== current.point.sequence ||
        expected.point.root !== current.point.root)) throw new Error('CELLD_GROUP_REVISION_CHANGED')
      return { revision: current, ...view.query(captured.sql, captured.bindings) }
    } finally { view.release() }
  }

  return Object.freeze({
    applicationId: session.applicationId,
    async transact(author: PeerIdentity, program: ChangeProgram, options: CommandOptions): Promise<{ readonly txId: string }> {
      requireGrant(author.publicKey, 'writer')
      const submission = await session.submitProgramAs(program, author, options)
      return { txId: submission.attemptId }
    },
    async outcome(author: string, txId: string): Promise<OperationState | null> {
      requireGrant(author, 'reader')
      const outcome = await session.operationByAttempt(txId, author)
      requireGrant(author, 'reader')
      return outcome
    },
    query,
    subscribe(author: string, input: GroupQuery, options: { readonly signal?: AbortSignal } = {}): AsyncIterable<CelldGroupQueryResult> {
      requireGrant(author, 'reader')
      const captured = structuredClone(input)
      return deferredStream(async signal => ({
        async *[Symbol.asyncIterator]() {
          requireGrant(author, 'reader')
          let previous: PeerRevision | undefined
          for await (const _change of session.changes({ signal })) {
            const result = await query(author, captured)
            signal.throwIfAborted()
            requireGrant(author, 'reader')
            const current = result.revision
            if (previous?.generation === current.generation && previous.point.root === current.point.root &&
              previous.materializationRevision === current.materializationRevision) continue
            previous = current
            yield result
          }
        },
      }), {
        signal: options.signal === undefined ? session.signal : AbortSignal.any([session.signal, options.signal]),
        concurrentNextError: 'CELLD_GROUP_QUERY_CONCURRENT_NEXT', abort: 'done',
      })
    },
  })
}

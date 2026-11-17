import { bytesToBase64Url } from '@chronolog/protocol'
import { describe, expect, it, vi } from 'vitest'

import { InProcessRpcTransport } from './in-process.js'
import { AsyncQueue } from './async-queue.js'
import { NodeRpcService } from './node-service.js'
import type { ChronologRpcNodeService, EnrollmentRpcService } from './service-contract.js'

const groupId = new Uint8Array(32).fill(1)
const group = bytesToBase64Url(groupId)

function readerNode(): ChronologRpcNodeService {
  const node: Pick<ChronologRpcNodeService, 'groupId' | 'revision' | 'materializedRevision' | 'orderLength' |
    'finalRevision' | 'finalOrderLength' | 'executionManifestDigest' | 'localSql'> = {
    groupId, revision: 8n, materializedRevision: 6n, orderLength: 3,
    finalRevision: 2n, finalOrderLength: 1, executionManifestDigest: new Uint8Array(32).fill(2),
    localSql(_sql, _parameters, options) {
      const final = options?.view === 'final'
      return { revision: final ? 2n : 6n, orderLength: final ? 1 : 3,
        columns: [{ name: 'value' }], rows: [[{ kind: 'integer', value: final ? '10' : '30' }]] }
    },
  }
  return node as ChronologRpcNodeService
}

describe('NodeRpcService policy views and enrollment', () => {
  it.each([true, false])('reports retained-route connectivity %s without inventing feed peers', async (connected) => {
    const service = new NodeRpcService({ node: {
      ...readerNode(),
      controlStore: { missingProposalCount: 0 },
      async status() {
        return { started: true, materializedRevision: 6n, orderLength: 3, validating: false,
          processedTransportRecords: 1, materializationPending: false, quarantinedFeeds: [],
          transport: { records: 1, peers: [], connected } }
      },
    } })
    const result = await service.getReplicationStatus({ groupId: group, requestId: 'status' }, { method: 'node.getReplicationStatus' })
    expect(result).toMatchObject({ state: connected ? 'current' : 'offline', connectedPeers: 0, knownPeers: 0 })
  })

  it('delivers new finality after reconnecting with a cursor from an older process', async () => {
    let revision = 1n
    let finalized = false
    let released = false
    const events = new AsyncQueue<bigint>()
    const node: ChronologRpcNodeService = {
      ...readerNode(),
      get revision() { return revision },
      candidate: () => ({ state: 'admissible', orderKey: { authorTimestampMs: 1n, authorId: groupId, txId: groupId } }),
      outcome: () => ({ outcome: 'accepted', rejectionCode: null, failingStatementIndex: null }),
      isFinal: () => finalized,
      outcomeChangedByReplay: () => false,
      revisions(after = 0n, signal) {
        signal?.addEventListener('abort', () => { released = true; events.close() }, { once: true })
        return { async *[Symbol.asyncIterator]() { for await (const event of events) if (event > after) yield event } }
      },
    }
    const service = new NodeRpcService({ node })
    const stream = service.streamOutcome({ groupId: group, requestId: 'watch', transactionId: 'tx-1', resumeAfterEventSetRevision: '1000' },
      { method: 'transaction.streamOutcome', signal: AbortSignal.timeout(1_000) })[Symbol.asyncIterator]()
    expect((await stream.next()).value).toMatchObject({ final: false, eventSetRevision: '1' })
    const next = stream.next()
    revision = 2n
    finalized = true
    events.push(revision)
    expect((await next).value).toMatchObject({ final: true, eventSetRevision: '2' })
    await stream.return?.()
    expect(released).toBe(true)
  })

  it('does not label a stale speculative result final across an asynchronous status refresh', async () => {
    let finalized = false
    const node = readerNode()
    const service = new NodeRpcService({ node: {
      ...node,
      candidate: () => ({ state: 'admissible', orderKey: { authorTimestampMs: 1n, authorId: groupId, txId: groupId } }),
      outcome: () => ({ outcome: finalized ? 'rejected' : 'accepted', rejectionCode: finalized ? 'constraint' : null, failingStatementIndex: finalized ? 0 : null }),
      isFinal: () => finalized,
      outcomeChangedByReplay: () => finalized,
      async status() {
        // A slow status read can overlap a replay and final-prefix publication.
        await Promise.resolve()
        finalized = true
        return { started: true, materializedRevision: 7n, orderLength: 3, validating: false,
          processedTransportRecords: 1, materializationPending: false, quarantinedFeeds: [], transport: { records: 1, peers: [] } }
      },
    } })
    const value = await service.getOutcome({ groupId: group, requestId: 'outcome', transactionId: 'tx-1' }, { method: 'transaction.getOutcome' })
    expect(value.outcome.type === 'accepted' && value.final).toBe(false)
  })

  it('selects the actual SQL reader and labels its revision and immutable prefix', async () => {
    const transport = new InProcessRpcTransport(new NodeRpcService({ node: readerNode() }))
    const request = { groupId: group, requestId: 'query', sql: 'SELECT value FROM t', parameters: [] }
    const local = await transport.unary('query.localSql', { ...request, view: 'local' })
    const final = await transport.unary('query.localSql', request)
    expect(local.result.rows).toEqual([[{ kind: 'integer', value: '30' }]])
    expect(local.revision).toMatchObject({ view: 'local', materializedRevision: '6', publishedOrderLength: '3', finalRevision: '2', finalOrderLength: '1' })
    expect(final.result.rows).toEqual([[{ kind: 'integer', value: '10' }]])
    expect(final.revision).toMatchObject({ view: 'final', materializedRevision: '2', publishedOrderLength: '1', finalRevision: '2', finalOrderLength: '1' })
    await expect(transport.unary('query.localSql', { ...request, view: 'final', atRevision: '6' }))
      .rejects.toMatchObject({ code: 'revision_unavailable' })
    await transport.close()
  })

  it('defaults direct live SQL requests to final and separates local cursor identities', async () => {
    const transport = new InProcessRpcTransport(new NodeRpcService({ node: {
      ...readerNode(),
      revisions() { return { async *[Symbol.asyncIterator]() {} } },
    } }))
    const request = { groupId: group, requestId: 'live-query', sql: 'SELECT value FROM t', parameters: [] }
    const final = transport.stream('query.liveSql', request)[Symbol.asyncIterator]()
    const local = transport.stream('query.liveSql', { ...request, view: 'local' })[Symbol.asyncIterator]()
    try {
      const finalSnapshot = (await final.next()).value
      const localSnapshot = (await local.next()).value
      expect(finalSnapshot).toMatchObject({ type: 'snapshot', revision: { view: 'final', materializedRevision: '2' },
        result: { rows: [[{ kind: 'integer', value: '10' }]] } })
      expect(localSnapshot).toMatchObject({ type: 'snapshot', revision: { view: 'local', materializedRevision: '6' },
        result: { rows: [[{ kind: 'integer', value: '30' }]] } })
      expect(finalSnapshot?.queryDigest).not.toBe(localSnapshot?.queryDigest)
    } finally {
      await final.return?.()
      await local.return?.()
      await transport.close()
    }
  })

  it('dispatches signed enrollment requests and receipts through the shared transport', async () => {
    const enrollment = {
      createRequest: vi.fn(async () => ({ signedRequest: 'signed-request' })),
      approveRequest: vi.fn(async () => ({ signedApproval: 'signed-approval' })),
      getStatus: vi.fn<EnrollmentRpcService['getStatus']>(async (request) => ({ requestId: request.requestId, state: 'awaiting-keys', missingEpochs: ['1'], roles: ['reader'] })),
    } satisfies EnrollmentRpcService
    const transport = new InProcessRpcTransport(new NodeRpcService({ node: readerNode(), enrollment }))
    const create = { groupId: group, requestId: 'join-device', roles: ['reader'] as const }
    expect(await transport.unary('enrollment.createRequest', create)).toEqual({ signedRequest: 'signed-request' })
    const approve = { groupId: group, requestId: 'approve-device', signedRequest: 'signed-request', roles: ['reader'] as const, grantFullHistory: true }
    expect(await transport.unary('enrollment.approveRequest', approve)).toEqual({ signedApproval: 'signed-approval' })
    const status = { groupId: group, requestId: 'join-device', signedApproval: 'signed-approval' }
    expect(await transport.unary('enrollment.getStatus', status)).toMatchObject({ state: 'awaiting-keys', missingEpochs: ['1'] })
    expect(enrollment.createRequest).toHaveBeenCalledWith(create)
    expect(enrollment.approveRequest).toHaveBeenCalledWith(approve)
    expect(enrollment.getStatus).toHaveBeenCalledWith(status)
    await expect(transport.unary('enrollment.createRequest', { ...create, groupId: 'another-group' }))
      .rejects.toMatchObject({ code: 'not_found' })
    await transport.close()
  })

  it('does not pretend enrollment exists on a replica without a configured service', async () => {
    const transport = new InProcessRpcTransport(new NodeRpcService({ node: readerNode() }))
    await expect(transport.unary('enrollment.createRequest', { groupId: group, requestId: 'join', roles: ['reader'] }))
      .rejects.toMatchObject({ code: 'failed_precondition' })
    await transport.close()
  })
})

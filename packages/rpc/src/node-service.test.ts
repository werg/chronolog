import { bytesToBase64Url } from '@chronolog/protocol'
import { describe, expect, it, vi } from 'vitest'

import { InProcessRpcTransport } from './in-process.js'
import { NodeRpcService } from './node-service.js'
import type { ChronologRpcNodeService, EnrollmentRpcService } from './service-contract.js'

const groupId = new Uint8Array(32).fill(1)
const group = bytesToBase64Url(groupId)

function readerNode(): ChronologRpcNodeService {
  return {
    groupId, revision: 8n, materializedRevision: 6n, orderLength: 3,
    finalRevision: 2n, finalOrderLength: 1, executionManifestDigest: new Uint8Array(32).fill(2),
    localSql(_sql, _parameters, options) {
      const final = options?.view === 'final'
      return { revision: final ? 2n : 6n, orderLength: final ? 1 : 3,
        columns: [{ name: 'value' }], rows: [[{ kind: 'integer', value: final ? '10' : '30' }]] }
    },
  } as ChronologRpcNodeService
}

describe('NodeRpcService policy views and enrollment', () => {
  it('selects the actual SQL reader and labels its revision and immutable prefix', async () => {
    const transport = new InProcessRpcTransport(new NodeRpcService({ node: readerNode() }))
    const request = { groupId: group, requestId: 'query', sql: 'SELECT value FROM t', parameters: [] }
    const local = await transport.unary('query.localSql', request)
    const final = await transport.unary('query.localSql', { ...request, view: 'final' })
    expect(local.result.rows).toEqual([[{ kind: 'integer', value: '30' }]])
    expect(local.revision).toMatchObject({ view: 'local', materializedRevision: '6', publishedOrderLength: '3', finalRevision: '2', finalOrderLength: '1' })
    expect(final.result.rows).toEqual([[{ kind: 'integer', value: '10' }]])
    expect(final.revision).toMatchObject({ view: 'final', materializedRevision: '2', publishedOrderLength: '1', finalRevision: '2', finalOrderLength: '1' })
    await expect(transport.unary('query.localSql', { ...request, view: 'final', atRevision: '6' }))
      .rejects.toMatchObject({ code: 'revision_unavailable' })
    await transport.close()
  })

  it('dispatches signed enrollment requests and receipts through the shared transport', async () => {
    const enrollment = {
      createRequest: vi.fn(async () => ({ signedRequest: 'signed-request' })),
      approveRequest: vi.fn(async () => ({ signedApproval: 'signed-approval' })),
      getStatus: vi.fn(async (request) => ({ requestId: request.requestId, state: 'awaiting-keys', missingEpochs: ['1'], roles: ['reader'] })),
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

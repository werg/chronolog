import { bytesToBase64Url } from '@chronolog/protocol'
import { DEFAULT_SIGNAL_TTL_MS, MAX_SIGNAL_TTL_MS, type EphemeralSignal } from '@chronolog/signals'
import { describe, expect, it, vi } from 'vitest'

import { InProcessRpcTransport } from './in-process.js'
import { NodeRpcService } from './node-service.js'
import type { ChronologRpcNodeService } from './service-contract.js'
import type { SignalSendRequest } from './types.js'

const groupId = new Uint8Array(32).fill(43), group = bytesToBase64Url(groupId)
function fixture() {
  let now = 1000
  const send = vi.fn(async () => ({ topic: 'typing' }) as EphemeralSignal)
  const node = { groupId } as ChronologRpcNodeService
  const service = new NodeRpcService({ node, now: () => now, signals: { send,
    subscribe: () => ({ async *[Symbol.asyncIterator]() {} }),
  } })
  return { send, transport: new InProcessRpcTransport(service), clock: (value: number) => { now = value } }
}
const request = { groupId: group, topic: 'typing', payload: true, ttlMs: 500, expiresAtMs: 1500 }

describe('live RPC deadline validation', () => {
  it.each([undefined, null, '1500', 0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects malformed absolute expiry %s before dispatch', async expiresAtMs => {
    const f = fixture()
    try {
      await expect(f.transport.unary('signals.send', { ...request, expiresAtMs } as SignalSendRequest))
        .rejects.toMatchObject({ code: 'invalid_argument', retryable: false, details: { signalCode: 'signal_options_invalid' } })
      expect(f.send).not.toHaveBeenCalled()
    } finally { await f.transport.close() }
  })

  it.each([0, -1, 1.5, NaN, Infinity, MAX_SIGNAL_TTL_MS + 1])('rejects invalid original TTL %s before dispatch', async ttlMs => {
    const f = fixture()
    try {
      await expect(f.transport.unary('signals.send', { ...request, ttlMs }))
        .rejects.toMatchObject({ code: 'invalid_argument', retryable: false, details: { signalCode: 'signal_ttl_invalid' } })
      expect(f.send).not.toHaveBeenCalled()
    } finally { await f.transport.close() }
  })

  it('caps the remaining lifetime at the original duration despite a clock offset', async () => {
    const f = fixture()
    try {
      await f.transport.unary('signals.send', { ...request, expiresAtMs: 20_000 })
      expect(f.send).toHaveBeenLastCalledWith('typing', true, expect.objectContaining({ ttlMs: 500 }))
      await f.transport.unary('signals.send', { groupId: group, topic: 'typing', payload: true, expiresAtMs: 20_000 })
      expect(f.send).toHaveBeenLastCalledWith('typing', true, expect.objectContaining({ ttlMs: DEFAULT_SIGNAL_TTL_MS }))
    } finally { await f.transport.close() }
  })

  it('does not revive an observed expired request after service clock rollback', async () => {
    const f = fixture()
    try {
      f.clock(1500)
      await expect(f.transport.unary('signals.send', request)).rejects.toMatchObject({ details: { signalCode: 'signal_expired' } })
      f.clock(1100)
      await expect(f.transport.unary('signals.send', request)).rejects.toMatchObject({ details: { signalCode: 'signal_expired' } })
      expect(f.send).not.toHaveBeenCalled()
    } finally { await f.transport.close() }
  })
})

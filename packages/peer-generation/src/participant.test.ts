import { describe, expect, it } from 'vitest'
import {
  CONTROL_PARTICIPANT_POLICY, PARTICIPANT_LIMITS, PEER_PARTICIPANT_POLICY,
  createParticipantRequest, createParticipantResponse, createParticipantTransport, participantAccepts,
  validateParticipantRequest, validateParticipantResponse,
} from './participant.js'

const scope = '11'.repeat(32)
const read = () => createParticipantRequest({ applicationId: scope, facet: 'control', action: 'read', payload: null })

describe('role-filtered participant transport', () => {
  it('rejects ordinary data and live signals before any hosted dispatch and at ingress', async () => {
    let calls = 0
    const transport = createParticipantTransport({ applicationId: scope, exchange: async request => {
      calls++; return createParticipantResponse(request, null)
    } })
    for (const [facet, action] of [['database', 'submit'], ['database', 'range'], ['content', 'chunk'], ['ephemeral', 'signal']] as const) {
      expect(participantAccepts(PEER_PARTICIPANT_POLICY, { facet, action })).toBe(true)
      expect(participantAccepts(CONTROL_PARTICIPANT_POLICY, { facet, action })).toBe(false)
      const request = createParticipantRequest({ applicationId: scope, facet, action, payload: { private: 'body' } }, PEER_PARTICIPANT_POLICY)
      expect(() => validateParticipantRequest(request)).toThrow('PEER_PARTICIPANT_FACET_FORBIDDEN')
      await expect(transport.exchange(request)).rejects.toThrow('PEER_PARTICIPANT_FACET_FORBIDDEN')
    }
    expect(calls).toBe(0)
  })
  it('matches responses to the exact scope, request and interest', async () => {
    const request = read(), response = createParticipantResponse(request, { controls: [] })
    expect(validateParticipantResponse(response, request).payload).toEqual({ controls: [] })
    for (const changed of [{ applicationId: '22'.repeat(32) }, { requestId: 'other' }, { action: 'select' }, { facet: 'publication' }]) {
      expect(() => validateParticipantResponse({ ...response, ...changed }, request)).toThrow('PEER_PARTICIPANT_RESPONSE_MISMATCH')
    }
    const transport = createParticipantTransport({ applicationId: scope,
      exchange: async () => ({ ...response, facet: 'database', action: 'range' }) })
    await expect(transport.exchange(request)).rejects.toThrow('PEER_PARTICIPANT_FACET_FORBIDDEN')
    await expect(transport.exchange({ ...request, applicationId: '22'.repeat(32) })).rejects.toThrow('PEER_PARTICIPANT_SCOPE_MISMATCH')
  })
  it('rejects envelope and payload accessors without evaluating or dispatching them', async () => {
    let calls = 0, reads = 0
    const transport = createParticipantTransport({ applicationId: scope, exchange: async request => {
      calls++; return createParticipantResponse(request, null)
    } })
    const changing = { ...read(), get facet(): 'control' | 'database' { return ++reads <= 3 ? 'control' : 'database' } }
    await expect(transport.exchange(changing)).rejects.toThrow('PEER_PARTICIPANT_ENVELOPE_INVALID')
    await expect(transport.request('control', 'select', { nested: { get transition() { reads++; return 'changed' } } }))
      .rejects.toThrow('PEER_PARTICIPANT_PAYLOAD_INVALID')
    expect(reads).toBe(0)
    expect(calls).toBe(0)
  })
  it('rejects payload serialization callbacks before they can change the routed interest', async () => {
    let calls = 0, serialized = false
    const transport = createParticipantTransport({ applicationId: scope, exchange: async request => {
      calls++; return createParticipantResponse(request, null)
    } })
    const request = { ...read(), payload: Object.assign([], { toJSON: () => {
      serialized = true; request.facet = 'database'; return []
    } }) }
    await expect(transport.exchange(request)).rejects.toThrow('PEER_PARTICIPANT_PAYLOAD_INVALID')
    expect(serialized).toBe(false)
    expect(calls).toBe(0)
  })
  it('bounds payloads and accepts finite schema constraints without broadening control canonicalization', () => {
    expect(createParticipantRequest({ applicationId: scope, facet: 'publication', action: 'definition',
      payload: { minimum: 0.25, maximum: 1.5 } }).payload).toEqual({ minimum: 0.25, maximum: 1.5 })
    expect(() => validateParticipantRequest({ ...read(), extra: null })).toThrow('PEER_PARTICIPANT_ENVELOPE_INVALID')
    expect(() => validateParticipantRequest({ ...read(), protocol: 'other' })).toThrow('PEER_PARTICIPANT_PROTOCOL_UNSUPPORTED')
    expect(() => validateParticipantRequest({ ...read(), payload: { invalid: Infinity } })).toThrow('PEER_PARTICIPANT_PAYLOAD_INVALID')
    expect(() => createParticipantRequest({ applicationId: scope, facet: 'ephemeral', action: 'invite',
      payload: 'x'.repeat(PARTICIPANT_LIMITS.bytes.ephemeral) })).toThrow('PEER_PARTICIPANT_SIZE_LIMIT')
    let payload: unknown = null
    for (let index = 0; index <= PARTICIPANT_LIMITS.depth; index++) payload = [payload]
    expect(() => validateParticipantRequest({ ...read(), payload })).toThrow('PEER_PARTICIPANT_DEPTH_LIMIT')
  })
  it('captures caller bytes, bounds pending work, and fences a cancelled response', async () => {
    const gates: Array<() => void> = [], observed: unknown[] = []
    const transport = createParticipantTransport({ applicationId: scope, exchange: async request => {
      await new Promise<void>(resolve => { gates.push(resolve) })
      observed.push(request.payload); return createParticipantResponse(request, request.payload)
    } })
    const payload = { transition: 'original' }, cancel = new AbortController()
    const request = createParticipantRequest({ applicationId: scope, facet: 'control', action: 'select', payload })
    const pending = Array.from({ length: PARTICIPANT_LIMITS.pending }, () => transport.exchange(request, { signal: cancel.signal }))
    payload.transition = 'mutated'
    await expect(transport.request('control', 'read', null)).rejects.toThrow('PEER_PARTICIPANT_BUSY')
    cancel.abort(new Error('cancelled'))
    for (const release of gates) release()
    const results = await Promise.allSettled(pending)
    expect(results.every(result => result.status === 'rejected')).toBe(true)
    expect(observed).toEqual(Array.from({ length: PARTICIPANT_LIMITS.pending }, () => ({ transition: 'original' })))
    const next = transport.request('control', 'read', null)
    gates.at(-1)!(); await expect(next).resolves.toBeNull()
  })
  it('settles cancelled callers before uncooperative dispatches release their bounded slots', async () => {
    const gates: Array<{ completion: Promise<unknown>; resolve: (value: unknown) => void; reject: (error: unknown) => void;
      response: ReturnType<typeof createParticipantResponse> }> = []
    const transport = createParticipantTransport({ applicationId: scope, exchange: request => {
      let resolve!: (value: unknown) => void, reject!: (error: unknown) => void
      const completion = new Promise<unknown>((accept, fail) => { resolve = accept; reject = fail })
      gates.push({ completion, resolve, reject, response: createParticipantResponse(request, 'delivered') })
      return completion
    } })
    const controller = new AbortController(), reason = new Error('caller left')
    const callers = Array.from({ length: PARTICIPANT_LIMITS.pending }, () =>
      transport.request('control', 'read', null, { signal: controller.signal }))
    const results = Promise.allSettled(callers)
    controller.abort(reason)
    // No physical exchange has settled: abort must not wait for these gates.
    expect(await results).toEqual(callers.map(() => ({ status: 'rejected', reason })))
    await expect(transport.request('control', 'read', null)).rejects.toThrow('PEER_PARTICIPANT_BUSY')
    expect(gates).toHaveLength(PARTICIPANT_LIMITS.pending)

    const physical = Promise.allSettled(gates.map(gate => gate.completion))
    gates.forEach((gate, index) => {
      if (index % 2 === 0) gate.resolve(gate.response)
      else gate.reject(new Error('late adapter failure'))
    })
    await physical
    const next = transport.request('control', 'read', null)
    expect(gates).toHaveLength(PARTICIPANT_LIMITS.pending + 1)
    gates.at(-1)!.resolve(gates.at(-1)!.response)
    await expect(next).resolves.toBe('delivered')
  })
})

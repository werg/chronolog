import { describe, expect, it } from 'vitest'
import { canonicalEventPayload, decodeChangeProgram, emit, encodeChangeProgram, program, type EventPayload } from './program.js'

describe('signed application programs', () => {
  it('canonically encodes literal events mixed with SQL and preserves step order', () => {
    const one = program('SELECT 1', emit('chat/message', { z: [true, null], a: 'hello' }), emit('task.claimed', { id: 'a' }))
    const two = program('SELECT 1', emit('chat/message', { a: 'hello', z: [true, null] }), emit('task.claimed', { id: 'a' }))
    expect(encodeChangeProgram(one)).toEqual(encodeChangeProgram(two))
    expect(decodeChangeProgram(encodeChangeProgram(one))).toEqual(one)
  })
  it.each([NaN, Infinity, undefined, 2n, new Date(), new Uint8Array([1]), Array<number>(2)])('rejects a lossy JSON payload %s', (value) => {
    expect(() => emit('topic', value as EventPayload)).toThrow()
  })
  it('rejects accessors without executing them and enforces payload/program budgets', () => {
    let calls = 0
    expect(() => canonicalEventPayload({ get x() { calls++; return 1 } })).toThrow()
    const array: number[] = []
    Object.defineProperty(array, '0', { enumerable: true, get() { calls++; return 1 } })
    expect(() => canonicalEventPayload(array)).toThrow()
    expect(calls).toBe(0)
    expect(() => emit('topic', 'a'.repeat(16_384))).toThrow()
    expect(() => program(...Array.from({ length: 65 }, () => emit('topic', null)))).toThrow()
    expect(() => emit('../bad topic', null)).toThrow()
  })
  it('captures payload values so later mutation cannot change a prepared event', () => {
    const payload = { body: ['original'] }
    const event = emit('chat/message', payload)
    payload.body.push('changed')
    expect(event.payload).toEqual({ body: ['original'] })
  })
})
